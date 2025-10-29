use natpmp::{Natpmp, Protocol, Response};
use std::net::Ipv4Addr;

/// Simplified response type for port mapping operations
#[derive(Debug, Clone)]
pub struct PortMappingResponse {
    pub external_port: u16,
}

/// Trait for port mapping operations to allow mocking in tests
#[cfg_attr(test, mockall::automock)]
pub trait PortMappingService: Send + Sync {
    /// Request a port mapping and return the response
    fn request_port_mapping(
        &mut self,
        protocol: Protocol,
        internal_port: u16,
        external_port: u16,
        duration: u32,
    ) -> Result<PortMappingResponse, String>;
}

/// NAT-PMP port mapping service implementation
pub struct NatpmpPortMappingService {
    client: Natpmp,
}

impl NatpmpPortMappingService {
    pub fn new(gateway: Ipv4Addr) -> Result<Self, String> {
        Natpmp::new_with(gateway)
            .map(|client| NatpmpPortMappingService { client })
            .map_err(|e| e.to_string())
    }
}

impl PortMappingService for NatpmpPortMappingService {
    fn request_port_mapping(
        &mut self,
        protocol: Protocol,
        internal_port: u16,
        external_port: u16,
        duration: u32,
    ) -> Result<PortMappingResponse, String> {
        // Send the port mapping request
        self.client
            .send_port_mapping_request(protocol, internal_port, external_port, duration)
            .map_err(|e| e.to_string())?;

        // NAT-PMP uses UDP, so we need to wait a bit for the gateway to respond
        // This is a protocol requirement, not a workaround
        std::thread::sleep(std::time::Duration::from_millis(250));

        // Read the response
        self.client
            .read_response_or_retry()
            .map(|response| {
                let external_port = match response {
                    Response::UDP(ur) => ur.public_port(),
                    Response::TCP(tr) => tr.public_port(),
                    _ => 0, // Shouldn't happen for port mapping requests
                };
                PortMappingResponse { external_port }
            })
            .map_err(|e| e.to_string())
    }
}
