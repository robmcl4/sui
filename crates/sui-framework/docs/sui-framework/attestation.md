---
title: Module `0x2::attestation`
---



-  [Function `nitro_attestation_verify_inner`](#0x2_attestation_nitro_attestation_verify_inner)
-  [Function `nitro_attestation_verify`](#0x2_attestation_nitro_attestation_verify)


<pre><code><b>use</b> <a href="clock.md#0x2_clock">0x2::clock</a>;
</code></pre>



<a name="0x2_attestation_nitro_attestation_verify_inner"></a>

## Function `nitro_attestation_verify_inner`

@param attestation: attesttaion documents bytes data.
@param enclave_pk: The public key created from enclave startup.
@param pcr0: Hash of enclave image file.
@param pcr1: Hash of linux kernel and bootstrap.
@param pcr2: Hash of application.
@param timestamp: The timestamp ms from clock object.

See https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
If the attestation verifies against the pcrs and against the root of aws trust, also the enclave public key equals to the attestation document's user data, return yes.


<pre><code><b>public</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify_inner">nitro_attestation_verify_inner</a>(<a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, timestamp: <a href="../move-stdlib/u64.md#0x1_u64">u64</a>): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>native</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify_inner">nitro_attestation_verify_inner</a>(
    <a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    timestamp: <a href="../move-stdlib/u64.md#0x1_u64">u64</a>
): bool;
</code></pre>



</details>

<a name="0x2_attestation_nitro_attestation_verify"></a>

## Function `nitro_attestation_verify`



<pre><code><b>public</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify">nitro_attestation_verify</a>(<a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;, <a href="clock.md#0x2_clock">clock</a>: &<a href="clock.md#0x2_clock_Clock">clock::Clock</a>): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="attestation.md#0x2_attestation_nitro_attestation_verify">nitro_attestation_verify</a>(
    <a href="attestation.md#0x2_attestation">attestation</a>: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    enclave_pk: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr0: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr1: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    pcr2: &<a href="../move-stdlib/vector.md#0x1_vector">vector</a>&lt;u8&gt;,
    <a href="clock.md#0x2_clock">clock</a>: &Clock
): bool {
    <a href="attestation.md#0x2_attestation_nitro_attestation_verify_inner">nitro_attestation_verify_inner</a>(<a href="attestation.md#0x2_attestation">attestation</a>, enclave_pk, pcr0, pcr1, pcr2, <a href="clock.md#0x2_clock_timestamp_ms">clock::timestamp_ms</a>(<a href="clock.md#0x2_clock">clock</a>))
}
</code></pre>



</details>
