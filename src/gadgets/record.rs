use super::{AddressGadget, UInt64Gadget};

#[derive(Clone, Debug)]
pub struct Record {
    pub owner: AddressGadget,
    pub gates: UInt64Gadget,
}
