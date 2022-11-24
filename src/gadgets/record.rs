use super::{UInt64Gadget, AddressGadget};

#[derive(Clone, Debug)]
pub struct Record {
    address: AddressGadget,
    gates: UInt64Gadget,
}

impl Record {
    pub fn new(address: AddressGadget, gates: UInt64Gadget) -> Self {
        Self { address, gates }
    }

    pub fn gates(&self) -> &UInt64Gadget {
        &self.gates
    }

    pub fn address(&self) -> &AddressGadget {
        &self.address
    }
}
