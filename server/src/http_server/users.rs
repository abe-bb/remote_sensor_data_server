use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct User {
    user: String,
    public_key: String,
}
