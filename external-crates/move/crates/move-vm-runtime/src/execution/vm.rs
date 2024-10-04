// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cache::{arena::ArenaPointer, move_cache::MoveCache},
    dbg_println,
    execution::{dispatch_tables::VMDispatchTables, interpreter},
    jit::runtime::ast::{Function, IntraPackageKey, Type, VTableKey},
    natives::extensions::NativeContextExtensions,
    runtime::data_cache::TransactionDataCache,
    shared::{
        gas::GasMeter,
        linkage_context::LinkageContext,
        serialization::{SerializedReturnValues, *},
    },
};
use move_binary_format::{
    errors::{Location, PartialVMError, PartialVMResult, VMResult},
    file_format::LocalIndex,
};
use move_core_types::{
    identifier::IdentStr,
    language_storage::{ModuleId, TypeTag},
    resolver::MoveResolver,
    vm_status::StatusCode,
};
use move_vm_config::runtime::VMConfig;
use std::{borrow::Borrow, sync::Arc};

// -------------------------------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------------------------------

/// A runnable Instance of a Virtual Machine. This is an instance with respect to some DataStore,
/// holding the Runtime VTables for that data store in order to invoke functions from it. This
/// instance is the main "execution" context for a virtual machine, allowing calls to
/// `execute_function` to run Move code located in the VM Cache.
///
/// Note this does NOT support publication. See `vm.rs` for publication.
#[allow(dead_code)]
pub struct MoveVM<'extensions, S: MoveResolver> {
    /// The VM cache
    pub(crate) virtual_tables: VMDispatchTables,
    /// The data store used to create this VM instance
    pub(crate) data_cache: TransactionDataCache<S>,
    /// The linkage context used to create this VM instance
    pub(crate) link_context: LinkageContext,
    /// Native context extensions for the interpreter
    pub(crate) native_extensions: NativeContextExtensions<'extensions>,
    /// An arc-lock reference to the VM's cache
    pub(crate) vm_cache: Arc<MoveCache>,
    /// The Move VM's configuration.
    pub(crate) vm_config: Arc<VMConfig>,
}

pub struct MoveVMFunction {
    function: ArenaPointer<Function>,
    pub parameters: Vec<Type>,
    pub return_type: Vec<Type>,
}

impl<'extensions, DataCache: MoveResolver> MoveVM<'extensions, DataCache> {
    // -------------------------------------------
    // Entry Points
    // -------------------------------------------

    /// Execute a Move function with the given arguments. This is mainly designed for an external
    /// environment to invoke system logic written in Move.
    ///
    /// NOTE: There are NO checks on the `args` except that they can deserialize into the provided
    /// types.
    /// The ability to deserialize `args` into arbitrary types is *very* powerful, e.g. it can
    /// used to manufacture `signer`'s or `Coin`'s from raw bytes. It is the responsibility of the
    /// caller (e.g. adapter) to ensure that this power is used responsibly/securely for its
    /// use-case.
    ///
    /// The caller MUST ensure
    ///   - All types and modules referred to by the type arguments exist.
    ///   - The signature is valid for the rules of the adapter
    ///
    /// The Move VM MUST return an invariant violation if the caller fails to follow any of the
    /// rules above.
    ///
    /// The VM will check that the function is marked as an 'entry' function.
    ///
    /// Currently if any other error occurs during execution, the Move VM will simply propagate that
    /// error back to the outer environment without handling/translating it. This behavior may be
    /// revised in the future.
    ///
    /// In case an invariant violation occurs, the whole Session should be considered corrupted and
    /// one shall not proceed with effect generation.
    pub fn execute_entry_function(
        &mut self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<Type>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        let bypass_declared_entry_check = false;
        self.execute_function(
            module,
            function_name,
            ty_args,
            args,
            gas_meter,
            bypass_declared_entry_check,
        )
    }

    /// Similar to execute_entry_function, but it bypasses visibility checks
    pub fn execute_function_bypass_visibility(
        &mut self,
        module: &ModuleId,
        function_name: &IdentStr,
        ty_args: Vec<Type>,
        args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        move_vm_profiler::gas_profiler_feature_enabled! {
            use move_vm_profiler::GasProfiler;
            if gas_meter.get_profiler_mut().is_none() {
                gas_meter.set_profiler(GasProfiler::init_default_cfg(
                    function_name.to_string(),
                    gas_meter.remaining_gas().into(),
                ));
            }
        }

        dbg_println!("running {module}::{function_name}");
        dbg_println!("tables: {:#?}", self.virtual_tables.loaded_packages);
        let bypass_declared_entry_check = true;
        self.execute_function(
            module,
            function_name,
            ty_args,
            args,
            gas_meter,
            bypass_declared_entry_check,
        )
    }

    pub fn vm_config(&self) -> &move_vm_config::runtime::VMConfig {
        &self.vm_config
    }

    pub fn load_type(&self, tag: &TypeTag) -> VMResult<Type> {
        self.virtual_tables.load_type(tag)
    }

    // -------------------------------------------
    // Execution Operations
    // -------------------------------------------

    /// Entry point for function execution, allowing an instance to run the specified function.
    /// Note that the specified module is a `runtime_id`, meaning it should already be resolved
    /// with respect to the linkage context.
    fn execute_function(
        &mut self,
        runtime_id: &ModuleId,
        function_name: &IdentStr,
        type_arguments: Vec<Type>,
        serialized_args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
        bypass_declared_entry_check: bool,
    ) -> VMResult<SerializedReturnValues> {
        // Find the function definition
        let MoveVMFunction {
            function,
            parameters,
            return_type,
        } = self.find_function(runtime_id, function_name, &type_arguments)?;

        if !bypass_declared_entry_check && !function.to_ref().is_entry {
            return Err(PartialVMError::new(
                StatusCode::EXECUTE_ENTRY_FUNCTION_CALLED_ON_NON_ENTRY_FUNCTION,
            )
            .finish(Location::Undefined));
        }

        // execute the function
        self.execute_function_impl(
            function,
            type_arguments,
            parameters,
            return_type,
            serialized_args,
            gas_meter,
        )
    }

    /// Find the function definition int the specified module and return the information required
    /// to do final verification and execution.
    pub(crate) fn find_function(
        &self,
        // This is expected to be the translated version of the module ID, already translated by
        // the link context. See `sui-adapter/src/programmable_transactions/execution.rs`
        runtime_id: &ModuleId,
        function_name: &IdentStr,
        ty_args: &[Type],
    ) -> VMResult<MoveVMFunction> {
        let (package_key, module_id) = runtime_id.clone().into();
        let member_name = function_name.into();
        let vtable_key = VTableKey {
            package_key,
            inner_pkg_key: IntraPackageKey {
                module_name: module_id,
                member_name,
            },
        };
        let _loaded_module = self
            .virtual_tables
            .resolve_loaded_module(runtime_id)
            .map_err(|err| err.finish(Location::Undefined))?;
        let function = self
            .virtual_tables
            .resolve_function(&vtable_key)
            .map_err(|err| err.finish(Location::Undefined))?;

        let fun_ref = function.to_ref();

        // See TODO on LoadedModule to avoid this work
        let parameters = fun_ref.parameters.clone();

        let return_ = fun_ref.return_.clone();

        // verify type arguments
        self.virtual_tables
            .verify_ty_args(fun_ref.type_parameters(), ty_args)
            .map_err(|e| e.finish(Location::Module(runtime_id.clone())))?;

        let function = MoveVMFunction {
            function,
            parameters,
            return_type: return_,
        };
        Ok(function)
    }

    /// Perform the actual execution, including setting up the interpreter machine, running the
    /// interpreter, and serializing the return value(s).
    fn execute_function_impl(
        &mut self,
        func: ArenaPointer<Function>,
        ty_args: Vec<Type>,
        param_types: Vec<Type>,
        return_types: Vec<Type>,
        serialized_args: Vec<impl Borrow<[u8]>>,
        gas_meter: &mut impl GasMeter,
    ) -> VMResult<SerializedReturnValues> {
        let arg_types = param_types
            .into_iter()
            .map(|ty| ty.subst(&ty_args))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|err| err.finish(Location::Undefined))?;
        let mut_ref_args = arg_types
            .iter()
            .enumerate()
            .filter_map(|(idx, ty)| match ty {
                Type::MutableReference(inner) => Some((idx, inner.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let (mut dummy_locals, deserialized_args) = deserialize_args(
            &self.virtual_tables,
            &self.vm_config,
            arg_types,
            serialized_args,
        )
        .map_err(|e| e.finish(Location::Undefined))?;
        let return_types = return_types
            .into_iter()
            .map(|ty| ty.subst(&ty_args))
            .collect::<PartialVMResult<Vec<_>>>()
            .map_err(|err| err.finish(Location::Undefined))?;

        let return_values = interpreter::run(
            func,
            ty_args,
            deserialized_args,
            &self.virtual_tables,
            self.vm_config.clone(),
            &mut self.native_extensions,
            gas_meter,
        )?;

        let serialized_return_values = serialize_return_values(
            &self.virtual_tables,
            &self.vm_config,
            &return_types,
            return_values,
        )
        .map_err(|e| e.finish(Location::Undefined))?;
        let serialized_mut_ref_outputs = mut_ref_args
            .into_iter()
            .map(|(idx, ty)| {
                // serialize return values first in the case that a value points into this local
                let local_val = dummy_locals.move_loc(
                    idx,
                    self.vm_config.enable_invariant_violation_check_in_swap_loc,
                )?;
                let (bytes, layout) =
                    serialize_return_value(&self.virtual_tables, &self.vm_config, &ty, local_val)?;
                Ok((idx as LocalIndex, bytes, layout))
            })
            .collect::<PartialVMResult<_>>()
            .map_err(|e| e.finish(Location::Undefined))?;

        // locals should not be dropped until all return values are serialized
        std::mem::drop(dummy_locals);

        Ok(SerializedReturnValues {
            mutable_reference_outputs: serialized_mut_ref_outputs,
            return_values: serialized_return_values,
        })
    }

    // -------------------------------------------
    // Into Methods
    // -------------------------------------------

    pub fn into_extensions(self) -> NativeContextExtensions<'extensions> {
        self.native_extensions
    }
}
