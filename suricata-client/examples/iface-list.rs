use serde_json::json;
use suricata_client::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect("/run/suricata/suricata-command.socket", false)?;
    client.send(&json!({"command": "iface-list"}))?;
    let response = client.read()?;
    dbg!(response);
    Ok(())
}
