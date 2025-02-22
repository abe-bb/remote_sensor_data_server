use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Sensor {
    pub name: String,
    fields: Vec<String>,
    field_types: Vec<FieldType>,
}

impl Sensor {
    pub fn new(name: String) -> Self {
        Sensor {
            name,
            fields: Vec::new(),
            field_types: Vec::new(),
        }
    }

    pub fn add_field(&mut self, name: String, field_type: FieldType) {
        self.fields.push(name);
        self.field_types.push(field_type);
    }
}

#[derive(Serialize, Deserialize)]
pub enum FieldType {
    Float,
    Integer,
}

#[cfg(test)]
mod tests {}
