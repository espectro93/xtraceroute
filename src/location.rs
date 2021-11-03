use std::net::IpAddr;
use std::error::Error;
use serde_json::Value;


pub fn get_location_for(ip: IpAddr) -> Result<String, Box<dyn Error>> {
    let geo_ip_data = reqwest::blocking::get("http://ip-api.com/json/".to_owned() + ip.to_string().as_str())?
        .json::<serde_json::Value>()?;

    let mut display = geo_ip_data.get("city").unwrap_or(&Value::String(String::from("No city"))).as_str().unwrap_or("No city").to_owned();
    let country = geo_ip_data.get("country").unwrap_or(&Value::String(String::from("No country"))).as_str().unwrap_or("No country").to_owned();

    display.push_str(", ");
    display.push_str(country.as_str());

    Ok(display)
}
