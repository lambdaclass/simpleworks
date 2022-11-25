use super::{UInt64Gadget, AddressGadget};

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: AddressGadget,
    pub gates: UInt64Gadget,
}
