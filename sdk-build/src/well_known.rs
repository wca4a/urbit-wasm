//! The well-known types an agent may use, and the definitions the SDK implements for them.
//!
//! The generated code takes every type in package `google.protobuf` from the SDK
//! (`pbjson-types`), whatever the files given to protoc declare there. So a definition that
//! differs from the SDK's would be advertised by the description and dropped or misread by the
//! handler. Two rules close that, both over the whole set before anything is written. A file
//! outside `google.protobuf` may refer only to the types listed here. And each listed type that
//! is referred to, directly or through another listed type, must be defined exactly as here.
//!
//! The definitions are written by hand. These types are frozen, and reading them from protoc or
//! from a file at build time would trust the very thing this checks. A test compares the table
//! with what the pinned `pbjson-types` encodes.

use std::io;

use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet, MessageOptions};

use crate::invalid;

/// One field of a well-known message, as the SDK implements it.
pub(crate) struct Field {
    pub(crate) name: &'static str,
    pub(crate) number: i32,
    pub(crate) label: Label,
    pub(crate) ty: Type,
    /// The full name of a message or enum type, with its leading dot; empty for a scalar.
    pub(crate) type_name: &'static str,
    pub(crate) oneof: Option<&'static str>,
}

/// A well-known message: its fields, its oneofs, and its nested messages (the map entry of
/// `Struct.fields`).
pub(crate) struct Message {
    pub(crate) name: &'static str,
    pub(crate) fields: &'static [Field],
    pub(crate) oneofs: &'static [&'static str],
    pub(crate) nested: &'static [Message],
    pub(crate) map_entry: bool,
}

pub(crate) enum Kind {
    Message(Message),
    Enum(&'static [(&'static str, i32)]),
}

const fn field(name: &'static str, number: i32, ty: Type) -> Field {
    Field { name, number, label: Label::Optional, ty, type_name: "", oneof: None }
}

const fn message(name: &'static str, fields: &'static [Field]) -> Kind {
    Kind::Message(Message { name, fields, oneofs: &[], nested: &[], map_entry: false })
}

/// A wrapper: one field, `value = 1`, of the type it wraps.
macro_rules! wrapper {
    ($name:literal, $ty:expr) => {
        ($name, Kind::Message(Message { name: $name, fields: &[field("value", 1, $ty)], oneofs: &[], nested: &[], map_entry: false }))
    };
}

const fn in_kind(name: &'static str, number: i32, ty: Type, type_name: &'static str) -> Field {
    Field { name, number, label: Label::Optional, ty, type_name, oneof: Some("kind") }
}

/// The well-known types an agent may use, all directly in package `google.protobuf`, with the
/// definitions the SDK implements (as protoc's own `.proto` files define them).
pub(crate) const SUPPORTED: [(&str, Kind); 18] = [
    ("Empty", message("Empty", &[])),
    ("Timestamp", message("Timestamp", &[field("seconds", 1, Type::Int64), field("nanos", 2, Type::Int32)])),
    ("Duration", message("Duration", &[field("seconds", 1, Type::Int64), field("nanos", 2, Type::Int32)])),
    ("Any", message("Any", &[field("type_url", 1, Type::String), field("value", 2, Type::Bytes)])),
    ("FieldMask", message("FieldMask", &[Field { name: "paths", number: 1, label: Label::Repeated, ty: Type::String, type_name: "", oneof: None }])),
    (
        "Struct",
        Kind::Message(Message {
            name: "Struct",
            fields: &[Field { name: "fields", number: 1, label: Label::Repeated, ty: Type::Message, type_name: ".google.protobuf.Struct.FieldsEntry", oneof: None }],
            oneofs: &[],
            nested: &[Message {
                name: "FieldsEntry",
                fields: &[
                    field("key", 1, Type::String),
                    Field { name: "value", number: 2, label: Label::Optional, ty: Type::Message, type_name: ".google.protobuf.Value", oneof: None },
                ],
                oneofs: &[],
                nested: &[],
                map_entry: true,
            }],
            map_entry: false,
        }),
    ),
    (
        "Value",
        Kind::Message(Message {
            name: "Value",
            fields: &[
                in_kind("null_value", 1, Type::Enum, ".google.protobuf.NullValue"),
                in_kind("number_value", 2, Type::Double, ""),
                in_kind("string_value", 3, Type::String, ""),
                in_kind("bool_value", 4, Type::Bool, ""),
                in_kind("struct_value", 5, Type::Message, ".google.protobuf.Struct"),
                in_kind("list_value", 6, Type::Message, ".google.protobuf.ListValue"),
            ],
            oneofs: &["kind"],
            nested: &[],
            map_entry: false,
        }),
    ),
    ("ListValue", message("ListValue", &[Field { name: "values", number: 1, label: Label::Repeated, ty: Type::Message, type_name: ".google.protobuf.Value", oneof: None }])),
    ("NullValue", Kind::Enum(&[("NULL_VALUE", 0)])),
    wrapper!("DoubleValue", Type::Double),
    wrapper!("FloatValue", Type::Float),
    wrapper!("Int64Value", Type::Int64),
    wrapper!("UInt64Value", Type::Uint64),
    wrapper!("Int32Value", Type::Int32),
    wrapper!("UInt32Value", Type::Uint32),
    wrapper!("BoolValue", Type::Bool),
    wrapper!("StringValue", Type::String),
    wrapper!("BytesValue", Type::Bytes),
];

const PREFIX: &str = ".google.protobuf.";

/// The messages an application file may extend: the standard options, for declaring custom
/// options. Extending anything else would add data no generated message holds.
const OPTION_MESSAGES: [&str; 9] = [
    ".google.protobuf.FileOptions",
    ".google.protobuf.MessageOptions",
    ".google.protobuf.FieldOptions",
    ".google.protobuf.OneofOptions",
    ".google.protobuf.EnumOptions",
    ".google.protobuf.EnumValueOptions",
    ".google.protobuf.ServiceOptions",
    ".google.protobuf.MethodOptions",
    ".google.protobuf.ExtensionRangeOptions",
];

/// A file of package `google.protobuf` or one under it; every other file is an application file.
pub(crate) fn is_well_known_file(file: &FileDescriptorProto) -> bool {
    file.package() == "google.protobuf" || file.package().starts_with("google.protobuf.")
}

fn supported(name: &str) -> Option<&'static Kind> {
    SUPPORTED.iter().find(|(known, _)| *known == name).map(|(_, kind)| kind)
}

fn listed() -> String {
    SUPPORTED.iter().map(|(name, _)| format!("google.protobuf.{name}")).collect::<Vec<_>>().join(", ")
}

/// The JSON name protoc gives a field by default: underscores dropped, each letter after one
/// made upper case.
pub(crate) fn default_json_name(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Refuse a reference to a `google.protobuf` type the SDK is not taken to supply, and a
/// definition of a supported one that is not exactly the SDK's.
pub(crate) fn check_well_known(fds: &FileDescriptorSet) -> io::Result<()> {
    let mut used: Vec<&'static str> = Vec::new();
    let mut note = |file: &FileDescriptorProto, place: String, type_name: &str| -> io::Result<()> {
        let Some(rest) = type_name.strip_prefix(PREFIX) else { return Ok(()) };
        let Some((name, _)) = SUPPORTED.iter().find(|(name, _)| *name == rest) else {
            return Err(invalid(format!(
                "{}: {place} refers to google.protobuf.{rest}, which is not supported in agent interfaces: the well-known types an agent may use are {}",
                file.name(),
                listed()
            )));
        };
        if !used.contains(name) {
            used.push(*name);
        }
        Ok(())
    };
    for file in &fds.file {
        // A well-known file declares types, not services: a service there would take the SDK's
        // types for whatever the file declares. The definitions of the package refer to its own
        // types; what they define is checked below, for the types that are used.
        if is_well_known_file(file) {
            if let Some(service) = file.service.first() {
                return Err(invalid(format!(
                    "{}: package {} declares service {}: a file in google.protobuf or under it may not declare a service",
                    file.name(),
                    file.package(),
                    service.name()
                )));
            }
            continue;
        }
        // An extension may only extend a standard option message (to declare a custom option),
        // and its type goes through the same check as any field's. The extendee itself is not a
        // reference to a type an interface uses.
        let extendee = |place: &str, extension: &prost_types::FieldDescriptorProto| -> io::Result<()> {
            if OPTION_MESSAGES.contains(&extension.extendee()) {
                return Ok(());
            }
            Err(invalid(format!(
                "{}: {place} extends {}: an application file may only extend the standard option messages of google.protobuf, to declare a custom option",
                file.name(),
                extension.extendee().trim_start_matches('.')
            )))
        };
        for extension in &file.extension {
            let place = format!("extension {}.{}", file.package(), extension.name());
            extendee(&place, extension)?;
            note(file, place, extension.type_name())?;
        }
        // Fields of messages, nested ones included (a map's entry among them), extensions
        // declared in them, and methods' input and output.
        let mut stack: Vec<(String, &DescriptorProto)> = file.message_type.iter().map(|message| (format!("{}.{}", file.package(), message.name()), message)).collect();
        while let Some((full, message)) = stack.pop() {
            for field in &message.field {
                note(file, format!("field {full}.{}", field.name()), field.type_name())?;
            }
            for extension in &message.extension {
                let place = format!("extension {full}.{}", extension.name());
                extendee(&place, extension)?;
                note(file, place, extension.type_name())?;
            }
            stack.extend(message.nested_type.iter().map(|nested| (format!("{full}.{}", nested.name()), nested)));
        }
        for service in &file.service {
            for method in &service.method {
                let place = format!("method {}.{}.{}", file.package(), service.name(), method.name());
                note(file, place.clone(), method.input_type())?;
                note(file, place, method.output_type())?;
            }
        }
    }
    // The types the used ones reach through their own fields (Struct reaches Value, and Value
    // reaches NullValue, Struct and ListValue).
    let mut i = 0;
    while i < used.len() {
        if let Some(Kind::Message(message)) = supported(used[i]) {
            let mut reached = Vec::new();
            reach(message, &mut reached);
            for name in reached {
                if !used.contains(&name) {
                    used.push(name);
                }
            }
        }
        i += 1;
    }
    for name in used {
        let kind = supported(name).expect("a supported name");
        let mut differences = Vec::new();
        let mut found_in = None;
        for file in fds.file.iter().filter(|file| file.package() == "google.protobuf") {
            match kind {
                Kind::Message(expected) => {
                    if let Some(found) = file.message_type.iter().find(|message| message.name() == name) {
                        found_in = Some(file);
                        message_differences(found, expected, &format!("google.protobuf.{name}"), &mut differences);
                    }
                }
                Kind::Enum(expected) => {
                    if let Some(found) = file.enum_type.iter().find(|e| e.name() == name) {
                        found_in = Some(file);
                        enum_differences(found, expected, &format!("google.protobuf.{name}"), &mut differences);
                    }
                }
            }
        }
        let Some(found_in) = found_in else {
            return Err(invalid(format!("google.protobuf.{name} is used, but no file in the set defines it")));
        };
        let file = found_in.name();
        // The SDK's types have proto3 presence; the same fields in a proto2 or editions file
        // would not.
        if found_in.syntax() != "proto3" {
            let syntax = if found_in.syntax().is_empty() { "proto2" } else { found_in.syntax() };
            return Err(invalid(format!("{file}: google.protobuf.{name} is defined in a {syntax} file: a well-known type an agent uses must be defined in a proto3 file, as the SDK's is")));
        }
        if !differences.is_empty() {
            return Err(invalid(format!(
                "{file}: google.protobuf.{name} is not the definition the SDK implements ({}): the well-known types are supplied by the SDK and must keep their standard definitions",
                differences.join("; ")
            )));
        }
    }
    Ok(())
}

/// The supported types a message's fields name, its nested messages' included.
fn reach(message: &Message, out: &mut Vec<&'static str>) {
    for field in message.fields {
        if let Some(rest) = field.type_name.strip_prefix(PREFIX) {
            if let Some((name, _)) = SUPPORTED.iter().find(|(name, _)| *name == rest) {
                out.push(*name);
            }
        }
    }
    for nested in message.nested {
        reach(nested, out);
    }
}

/// What differs between a message as found and as the SDK implements it.
fn message_differences(found: &DescriptorProto, expected: &Message, path: &str, out: &mut Vec<String>) {
    for want in expected.fields {
        let Some(got) = found.field.iter().find(|got| got.name() == want.name) else {
            out.push(format!("{path} has no field {}", want.name));
            continue;
        };
        let at = format!("field {path}.{}", want.name);
        if got.number() != want.number {
            out.push(format!("{at} is number {}, not {}", got.number(), want.number));
        }
        if got.label() != want.label {
            out.push(format!("{at} is {}, not {}", got.label().as_str_name(), want.label.as_str_name()));
        }
        if got.r#type() != want.ty {
            out.push(format!("{at} is of type {}, not {}", got.r#type().as_str_name(), want.ty.as_str_name()));
        }
        if got.type_name() != want.type_name {
            out.push(format!("{at} names type {:?}, not {:?}", got.type_name(), want.type_name));
        }
        let json = default_json_name(want.name);
        if got.json_name.as_deref().unwrap_or(&json) != json {
            out.push(format!("{at} has the JSON name {:?}, not {json:?}", got.json_name()));
        }
        let oneof = got.oneof_index.and_then(|index| found.oneof_decl.get(usize::try_from(index).ok()?)).map(|oneof| oneof.name());
        if oneof != want.oneof {
            out.push(format!("{at} is in oneof {oneof:?}, not {:?}", want.oneof));
        }
        if got.proto3_optional.is_some() || got.options.is_some() || got.default_value.is_some() || got.extendee.is_some() {
            out.push(format!("{at} carries settings the SDK's does not (optional, options, a default or an extendee)"));
        }
    }
    for got in &found.field {
        if !expected.fields.iter().any(|want| want.name == got.name()) {
            out.push(format!("{path} has an extra field {} (number {})", got.name(), got.number()));
        }
    }
    let oneofs: Vec<&str> = found.oneof_decl.iter().map(|oneof| oneof.name()).collect();
    if oneofs != expected.oneofs || found.oneof_decl.iter().any(|oneof| oneof.options.is_some()) {
        out.push(format!("{path} has the oneofs {oneofs:?}, not {:?}", expected.oneofs));
    }
    for want in expected.nested {
        match found.nested_type.iter().find(|got| got.name() == want.name) {
            Some(got) => message_differences(got, want, &format!("{path}.{}", want.name), out),
            None => out.push(format!("{path} has no nested message {}", want.name)),
        }
    }
    for got in &found.nested_type {
        if !expected.nested.iter().any(|want| want.name == got.name()) {
            out.push(format!("{path} has an extra nested message {}", got.name()));
        }
    }
    if !found.enum_type.is_empty() || !found.extension.is_empty() || !found.extension_range.is_empty() || !found.reserved_range.is_empty() || !found.reserved_name.is_empty() {
        out.push(format!("{path} has nested enums, extensions, extension ranges or reservations the SDK's does not"));
    }
    let options = expected.map_entry.then(|| MessageOptions { map_entry: Some(true), ..Default::default() });
    if found.options != options {
        out.push(format!("{path} has message options {:?}, not {options:?}", found.options));
    }
}

/// What differs between an enum as found and as the SDK implements it.
fn enum_differences(found: &EnumDescriptorProto, expected: &[(&str, i32)], path: &str, out: &mut Vec<String>) {
    let values: Vec<(&str, i32)> = found.value.iter().map(|value| (value.name(), value.number())).collect();
    if values != expected {
        out.push(format!("{path} has the values {values:?}, not {expected:?}"));
    }
    if found.options.is_some() || found.value.iter().any(|value| value.options.is_some()) || !found.reserved_range.is_empty() || !found.reserved_name.is_empty() {
        out.push(format!("{path} has options or reservations the SDK's does not"));
    }
}
