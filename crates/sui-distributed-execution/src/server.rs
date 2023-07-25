use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use super::agents::*;
use super::types::*;

pub struct Server<T: Agent<M>, M: Debug + Message + Send + 'static> {
    global_config: GlobalConfig,
    my_id: UniqueId,
    agent_type: PhantomData<T>,
    msg_type: PhantomData<M>
}

impl<T: Agent<M>, M: Debug + Message + Send + 'static> Server<T, M> {
    pub fn new(global_config: GlobalConfig, my_id: UniqueId) -> Self {
        Server {
            global_config,
            my_id,
            agent_type: PhantomData,
            msg_type: PhantomData,
        }
    }

    // Helper function to initialize Agent
    fn init_agent(id: UniqueId, conf: AppConfig) 
    -> (T,
        mpsc::Sender<NetworkMessage<M>>,
        mpsc::Receiver<NetworkMessage<M>>,) 
    {
        let (in_send, in_recv) = mpsc::channel(100);
        let (out_send, out_recv) = mpsc::channel(100);
        let agent = T::new(id, in_recv, out_send, conf.attrs);
        return (agent, in_send, out_recv);
    }

    // Server main function
    pub async fn run(&mut self) {

        // Initialize map from id to address
        let mut addr_table: HashMap<UniqueId, (IpAddr, u16)> = HashMap::new();
        for (id, entry) in &self.global_config {
            assert!(!addr_table.contains_key(&id), "ids must be unique");
            addr_table.insert(*id, (entry.ip_addr, entry.port));
        }

        // Initialize Agent and Network Manager
        let agent_config = self.global_config.get(&self.my_id).unwrap().clone();
        let (mut agent, in_sender, out_receiver) = 
            Self::init_agent(self.my_id, agent_config);
             
        let mut network_manager = NetworkManager::new(
            self.my_id, addr_table, 
            in_sender, 
            out_receiver);

        // Run the Network Manager
        tokio::spawn(async move {
            network_manager.run().await;
        });

        // Wait for connections to be set up
        sleep(Duration::from_millis(1_000)).await;

        // Run the agent
        agent.run().await;
    }
}



/*****************************************************************************************
 *                                     Network Manager                                   *
 *****************************************************************************************/

// Network Manager spawns and manages TCP connections

struct NetworkManager<M: Debug + Message + Send> {
    my_id: UniqueId,
    my_addr: IpAddr,    // listening addr
    my_port: u16,       // listening port
    addr_table: HashMap<UniqueId, (IpAddr, u16)>,
    application_in: mpsc::Sender<NetworkMessage<M>>,     // incoming messages for server
    application_out: mpsc::Receiver<NetworkMessage<M>>,  // outgoing messages from server
}

impl<M: Debug + Message + Send + 'static> NetworkManager<M> {
    fn new(
        my_id: UniqueId,
        addr_table: HashMap<UniqueId, (IpAddr, u16)>,
        application_in: mpsc::Sender<NetworkMessage<M>>,
        application_out: mpsc::Receiver<NetworkMessage<M>>
    ) -> Self {
        NetworkManager {
            my_id,
            my_addr: addr_table.get(&my_id).unwrap().0,
            my_port: addr_table.get(&my_id).unwrap().1,
            addr_table,
            application_in,
            application_out,
        }
    }

    async fn handle_connection(
        my_id:UniqueId,
        socket: TcpStream, 
        in_sender: mpsc::Sender<NetworkMessage<M>>,   // Send channel from link to Network Manager
        receiver_table: Arc<RwLock<HashMap<UniqueId, mpsc::Receiver<NetworkMessage<M>>>>>) 
    {
        let mut stream = BufReader::new(socket);

        // First perform handshake. Send my id, receive remote_id, and pick appropriate
        // receiver from receiver_table.
        let msg = format!("{}\n", my_id);
        stream.write_all(msg.as_bytes()).await.unwrap();

        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        let remote_id = line.trim().parse().unwrap();
        println!("Established connection with {}", remote_id);

        let mut out_receiver: mpsc::Receiver<NetworkMessage<M>>; 
        {
            let mut w_receiver_table = receiver_table.write().unwrap();
            out_receiver = w_receiver_table.remove(&remote_id).unwrap();
        }

        loop {
            line = String::new();
            tokio::select! {
                Some(message) = out_receiver.recv() => {
                    let serialized = message.serialize();
                    stream.write_all(serialized.as_bytes()).await.expect("send failed");
                }
                Ok(_) = stream.read_line(&mut line) => {
                    if line.len() == 0 {
                        panic!("Connection with remote id {remote_id} broken");
                    }
                    let message = NetworkMessage::deserialize(line);

                    // TODO: network manager may want to assign the source, rather than
                    // check it. There could be a Send() abstraction where the sender doesn't
                    // have to specify the source.
                    assert!(message.src == remote_id);

                    in_sender.send(message).await.expect("send failed");
                }
            }
        }
    }

    async fn run(&mut self) {     

        // Initialize routing table
        let mut routing_table = HashMap::<UniqueId, mpsc::Sender<NetworkMessage<M>>>::new();
        let receiver_table = Arc::new(RwLock::new(
            HashMap::<UniqueId, mpsc::Receiver<NetworkMessage<M>>>::new()
        ));
        {
            let mut w_receiver_table = receiver_table.write().unwrap();
            for (&id, _) in &self.addr_table {
                // Channel from Network Manager to link handler
                let (out_sender, out_receiver) = mpsc::channel::<NetworkMessage<M>>(100);
                
                routing_table.insert(id, out_sender);
                w_receiver_table.insert(id, out_receiver);
            }
        }
       
        let receiver_table_clone = receiver_table.clone();
   
        // Channel from link handlers to Network Manager
        let (in_sender, mut in_receiver) = mpsc::channel::<NetworkMessage<M>>(100);
        let in_sender_clone = in_sender.clone();

        // Listen for incoming connections
        let listener_address = SocketAddr::new(self.my_addr, self.my_port);
        let my_id = self.my_id.clone();

        tokio::spawn(async move {
            let listener = TcpListener::bind(listener_address).await.unwrap();
            println!("Server {} listening on {}", my_id, listener_address);
            
            // Accept incoming connections and spawn a handle_connection task for each
            while let Ok((socket, _)) = listener.accept().await {
                let in_sender_clone = in_sender_clone.clone();
                let receiver_table_clone = receiver_table_clone.clone();

                tokio::spawn(async move {
                    Self::handle_connection(my_id, socket, in_sender_clone, receiver_table_clone).await;
                });
            }
        });

        // Connect to servers with lower id
        for (&id, &(ip, port)) in &self.addr_table {
            if id < self.my_id {
                let remote = SocketAddr::new(ip, port);
                let socket = TcpStream::connect(remote).await.unwrap();
                let in_sender_clone = in_sender.clone();
                let receiver_table_clone = receiver_table.clone();

                tokio::spawn(async move {
                    Self::handle_connection(my_id, socket, in_sender_clone, receiver_table_clone).await;
                });
            }
        }

        // Receive loop to manage incoming TCP messages, 
        // and route outgoing messages from application to the right link
        loop {
            tokio::select! {
                // NetManager from tcp
                Some(message) = in_receiver.recv() => {
                    self.application_in.send(message).await.expect("send failed");
                }
                // NetManager from application
                Some(message) = self.application_out.recv() => {
                    let dst = message.dst;
                    let out_chan = routing_table.get(&dst).unwrap().clone();
                    out_chan.send(message).await.expect("send failed");
                }
            }
        }
    }
}
