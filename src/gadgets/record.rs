use super::{UInt64Gadget, AddressGadget};

#[derive(Clone, Debug)]
pub struct Record {
    pub address: AddressGadget,
    pub gates: UInt64Gadget,
}
