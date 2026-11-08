//! Wire-level migration checks against a private bus with synthetic data only.
use super::*;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/test";
const SESSION_PATH: &str = "/org/freedesktop/secrets/session/test";
const ITEM_PATH: &str = "/org/freedesktop/secrets/collection/test/item";

fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

struct Bus(Child);
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Default)]
struct State {
    unlocked: Arc<AtomicBool>,
    closes: Arc<AtomicUsize>,
    added: Arc<AtomicBool>,
    deleted: Arc<AtomicBool>,
}

struct Service(State);
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn read_alias(&self, alias: &str) -> OwnedObjectPath {
        assert_eq!(alias, "default");
        path(COLLECTION_PATH)
    }
    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![path(COLLECTION_PATH)]
    }
    fn open_session(&self, algorithm: &str, input: Variant<'_>) -> (OwnedVariant, OwnedObjectPath) {
        assert_eq!(algorithm, "plain");
        assert_eq!(<&str>::try_from(&input).unwrap(), "");
        (Variant::from("").try_into().unwrap(), path(SESSION_PATH))
    }
    fn get_secrets(&self, items: Vec<OwnedObjectPath>, session: OwnedObjectPath) -> HashMap<OwnedObjectPath, Secret> {
        assert_eq!(items, vec![path(ITEM_PATH)]);
        assert_eq!(session, path(SESSION_PATH));
        HashMap::from([(path(ITEM_PATH), (session, vec![], b"synthetic secret".to_vec(), "text/plain".into()))])
    }
    fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.0.unlocked.store(false, Ordering::SeqCst);
        (objects, path("/"))
    }
}

struct Session(State);
#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self) {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
    }
}

struct Gnome(State);
#[zbus::interface(name = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface")]
impl Gnome {
    fn unlock_with_master_password(&self, collection: OwnedObjectPath, secret: Secret) -> zbus::fdo::Result<()> {
        assert_eq!(collection, path(COLLECTION_PATH));
        assert_eq!(secret.0, path(SESSION_PATH));
        assert!(secret.1.is_empty());
        assert_eq!(secret.3, "text/plain");
        if secret.2 != b"synthetic password" {
            return Err(zbus::fdo::Error::AccessDenied("Wrong synthetic password".into()));
        }
        self.0.unlocked.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct MockCollection(State);
#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl MockCollection {
    #[zbus(property)]
    fn label(&self) -> &str {
        "Synthetic collection"
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.0.unlocked.load(Ordering::SeqCst)
    }
    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        vec![path(ITEM_PATH)]
    }
    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        assert_eq!(attributes, HashMap::from([("synthetic".into(), "value".into())]));
        vec![path(ITEM_PATH)]
    }
    fn create_item(
        &self,
        properties: HashMap<String, OwnedVariant>,
        secret: Secret,
        replace: bool,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        assert_eq!(properties.len(), 2);
        assert!(!replace);
        assert_eq!(secret.0, path(SESSION_PATH));
        assert_eq!(secret.2, b"synthetic secret");
        self.0.added.store(true, Ordering::SeqCst);
        (path(ITEM_PATH), path("/"))
    }
    fn delete(&self) -> OwnedObjectPath {
        self.0.deleted.store(true, Ordering::SeqCst);
        path("/")
    }
}

struct MockItem;
#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl MockItem {
    #[zbus(property)]
    fn label(&self) -> &str {
        "Synthetic item"
    }
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        HashMap::from([("synthetic".into(), "value".into())])
    }
}

#[test]
fn private_bus_preserves_secret_service_contract_and_closes_failed_sessions() {
    // Never use or activate a service on the developer's real session bus.
    let mut bus = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Install dbus-daemon for private-bus tests"));
    let mut address = String::new();
    BufReader::new(bus.0.stdout.take().unwrap()).read_line(&mut address).unwrap();
    let state = State::default();
    let _server = block_on(
        zbus::connection::Builder::address(address.trim())
            .name(DEST)
            .serve_at(SERVICE_PATH, Service(state.clone()))
            .serve_at(SERVICE_PATH, Gnome(state.clone()))
            .serve_at(SESSION_PATH, Session(state.clone()))
            .serve_at(COLLECTION_PATH, MockCollection(state.clone()))
            .serve_at(ITEM_PATH, MockItem)
            .build(),
    )
    .unwrap();
    let keyring = Keyring { conn: block_on(zbus::connection::Builder::address(address.trim()).build()).unwrap() };
    let collection = keyring.default_collection().unwrap();
    assert_eq!(collection.label, "Synthetic collection");
    assert_eq!(keyring.collections().unwrap().len(), 1);
    assert!(keyring.locked(&collection).unwrap());
    assert!(keyring.unlock(&collection, b"wrong").is_err());
    assert_eq!(state.closes.load(Ordering::SeqCst), 1);
    keyring.unlock(&collection, b"synthetic password").unwrap();
    assert!(!keyring.locked(&collection).unwrap());
    let items = keyring.items(&collection).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].secret.as_slice(), b"synthetic secret");
    assert!(keyring.contains(&collection, &items[0].attributes).unwrap());
    keyring.add(&collection, &items[0]).unwrap();
    assert!(state.added.load(Ordering::SeqCst));
    assert_eq!(state.closes.load(Ordering::SeqCst), 4);
    keyring.lock(&collection).unwrap();
    assert!(keyring.locked(&collection).unwrap());
    keyring.delete(&collection).unwrap();
    assert!(state.deleted.load(Ordering::SeqCst));
}
