use std::net::IpAddr;
use std::error::Error;


pub fn get_location_for(ip: IpAddr) -> Result<String, Box<dyn Error>> {
    let geo_ip_data = reqwest::blocking::get("https://api.ipgeolocationapi.com/geolocate/".to_owned() + ip.to_string().as_str())?
        .json::<serde_json::Value>()?;

    let lat = geo_ip_data.get("geo").unwrap().get("latitude").unwrap();
    let lng = geo_ip_data.get("geo").unwrap().get("longitude").unwrap();

    let location_request = format!("http://nominatim.openstreetmap.org/reverse?format=json&lat={}&lon={}&zoom=18&addressdetails=1", lat, lng);
    let location_for_geo = reqwest::blocking::get(location_request)?.json::<serde_json::Value>()?;

    Ok(location_for_geo.get("display_name").unwrap().to_string())
}
