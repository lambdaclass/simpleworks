use super::UInt64Gadget;

#[derive(Clone)]
pub struct Record {
    gates: UInt64Gadget,
}

impl Record {
    pub fn new(gates: UInt64Gadget) -> Self {
        Self { gates }
    }

    pub fn gates(&self) -> &UInt64Gadget {
        &self.gates
    }
}
