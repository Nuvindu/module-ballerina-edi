// Copyright (c) 2023 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/io;

type EdiContext record {|
    EdiSchema schema;
    string[] ediText = [];
    int rawIndex = 0;
|};

# Reads the given EDI text according to the provided schema.
# When the schema declares an `envelope`, envelope segments are skipped and only the
# single transaction body is parsed; use `interchangeFromEdiString` for multi-transaction input.
#
# + ediText - EDI text to be read
# + schema - Schema of the EDI text
# + return - JSON value containing the EDI data, or an `Error` when reading fails
public isolated function fromEdiString(string ediText, EdiSchema schema) returns json|Error {
    EdiContext context = {schema};
    EdiUnitSchema[] currentMapping = context.schema.segments;

    string text = ediText;
    EdiEnvelopeSchema? env = schema.envelope;
    if env is EdiEnvelopeSchema {
        check checkEnvelopeFixedLengthSupport(schema);
        text = stripBom(text);
        text = check stripUnaIfPresent(text, schema);
    }
    context.ediText = check splitSegments(text, context.schema.delimiters.segment);

    if env is EdiEnvelopeSchema {
        context.ediText = check stripEnvelopeSegmentsPositional(context.ediText, env, schema.delimiters.'field);
    } else {
        // No envelope schema: detect X12 (ST) or EDIFACT (UNH) transaction boundaries.
        // Use the standard transaction-start code rather than schema.segments[0].code,
        // which may be "ISA" (appears once per interchange, not per transaction).
        string trimmedText = text.trim();
        string txnStartCode = trimmedText.startsWith("ISA") ? "ST" : "UNH";
        string fieldDelim = schema.delimiters.'field;
        int txnCount = 0;
        foreach string seg in context.ediText {
            if getSegmentCode(seg.trim(), fieldDelim) == txnStartCode {
                txnCount += 1;
            }
        }
        if txnCount > 1 {
            // Multiple transactions: split into individual EDI strings, parse each,
            // then merge by combining repeatable (array) fields from all transactions.
            string[] singles = check splitTransactionStrings(ediText, schema);
            json result = check fromEdiString(singles[0], schema);
            foreach int i in 1 ..< singles.length() {
                json txnBody = check fromEdiString(singles[i], schema);
                result = check mergeTransactionBodies(result, txnBody);
            }
            return result;
        }
    }

    EdiSegmentGroup rootGroup = check readSegmentGroup(currentMapping, context, true);
    return rootGroup;
}

// Splits a multi-transaction EDI text (schema has no envelope declaration) into
// individual single-transaction EDI strings. Detects X12 (ST/SE) or EDIFACT (UNH/UNT)
// boundaries from the raw segments and wraps each transaction with the original
// interchange and functional-group headers so that fromEdiString can parse each
// independently.
isolated function splitTransactionStrings(string ediText, EdiSchema schema) returns string[]|Error {
    string segTerm   = schema.delimiters.segment;
    string fieldDelim = schema.delimiters.'field;
    string[] rawSegs = check splitSegments(stripBom(ediText), segTerm);

    // Detect X12 vs EDIFACT from the leading segment of the first non-empty raw segment.
    boolean isX12 = false;
    foreach string s in rawSegs {
        string t = s.trim();
        if t.length() > 0 {
            isX12 = t.startsWith("ISA");
            break;
        }
    }

    string ixHdrCode  = isX12 ? "ISA" : "UNB";
    string grpHdrCode = isX12 ? "GS"  : "UNG";
    string txnStart   = isX12 ? "ST"  : "UNH";
    string txnEnd     = isX12 ? "SE"  : "UNT";
    string grpTrlCode = isX12 ? "GE"  : "UNE";
    string ixTrlCode  = isX12 ? "IEA" : "UNZ";

    string ixHdr      = "";
    string grpHdr     = "";
    string ixCtrlNum  = "";
    string grpCtrlNum = "";
    string[] currentTxn = [];
    boolean inTxn     = false;
    string[] result   = [];

    foreach string raw in rawSegs {
        string seg = raw.trim();
        if seg.length() == 0 { continue; }
        string code = getSegmentCode(seg, fieldDelim);

        if code == ixHdrCode {
            ixHdr = seg;
            string[] f = segmentFields(seg, fieldDelim);
            // X12 ISA13 (index 13) | EDIFACT UNB 0020 (index 5)
            ixCtrlNum = isX12 ? (f.length() > 13 ? f[13] : "") : (f.length() > 5 ? f[5] : "");
        } else if code == grpHdrCode {
            grpHdr = seg;
            string[] f = segmentFields(seg, fieldDelim);
            // X12 GS06 (index 6) | EDIFACT UNG 0048 (index 1)
            grpCtrlNum = isX12 ? (f.length() > 6 ? f[6] : "") : (f.length() > 1 ? f[1] : "");
        } else if code == txnStart {
            inTxn = true;
            currentTxn = [seg];
        } else if code == txnEnd && inTxn {
            currentTxn.push(seg);
            string single = "";
            if ixHdr.length() > 0 {
                single += ixHdr + segTerm + "\n";
            }
            if grpHdr.length() > 0 {
                single += grpHdr + segTerm + "\n";
            }
            foreach string s in currentTxn {
                single += s + segTerm + "\n";
            }
            if grpHdr.length() > 0 {
                single += grpTrlCode + fieldDelim + "1" + fieldDelim + grpCtrlNum + segTerm + "\n";
            }
            if ixHdr.length() > 0 {
                single += ixTrlCode + fieldDelim + "1" + fieldDelim + ixCtrlNum + segTerm;
            }
            result.push(single.trim());
            currentTxn = [];
            inTxn = false;
        } else if inTxn {
            currentTxn.push(seg);
        }
    }
    return result;
}

// Splits a segment string into its fields using the given field delimiter.
isolated function segmentFields(string seg, string delim) returns string[] {
    string[] parts = [];
    int startIdx = 0;
    int? pos = seg.indexOf(delim, startIdx);
    while pos is int {
        parts.push(seg.substring(startIdx, pos));
        startIdx = pos + delim.length();
        pos = seg.indexOf(delim, startIdx);
    }
    parts.push(seg.substring(startIdx));
    return parts;
}

// Merges two parsed transaction bodies into one by combining repeatable (array) fields
// from both. Nested maps are merged recursively. For scalar fields, the base value wins.
isolated function mergeTransactionBodies(json base, json addition) returns json|Error {
    if base !is map<json> || addition !is map<json> {
        return base;
    }
    map<json> baseMap = base;
    map<json> addMap = addition;
    map<json> result = {};
    foreach string k in baseMap.keys() {
        json? v = baseMap[k];
        if v is json {
            result[k] = v;
        }
    }
    foreach string k in addMap.keys() {
        json? addVal = addMap[k];
        if addVal is () {
            continue;
        }
        json? baseVal = result[k];
        if addVal is json[] && baseVal is json[] {
            json[] merged = [];
            foreach json item in baseVal {
                merged.push(item);
            }
            foreach json item in addVal {
                merged.push(item);
            }
            result[k] = merged;
        } else if addVal is map<json> && baseVal is map<json> {
            result[k] = check mergeTransactionBodies(baseVal, addVal);
        }
        // Scalar fields: base value wins (first transaction)
    }
    return result;
}

# Writes the given JSON varibale into a EDI text according to the provided schema.
#
# + msg - JSON value to be written into EDI
# + schema - Schema of the EDI text
# + return - EDI text containing the data provided in the JSON variable. Error if the reading fails.
public isolated function toEdiString(json msg, EdiSchema schema) returns string|Error {
    if msg !is map<json> {
        return error(string `Input is not compatible with the schema.`);
    }
    // Clone schema to prevent modifying originals with references.
    // `cloneWithType` returns a plain `error`, which is not a subtype of the
    // distinct `Error`, so `check` cannot be used here — cast instead.
    EdiSchema|error clonedSchema = schema.cloneWithType();
    if clonedSchema is error {
        return <Error>clonedSchema;
    }
    EdiContext context = {schema: clonedSchema};
    check writeSegmentGroup(msg, clonedSchema, context);
    string[] ediText = context.ediText;
    if ediText.length() == 0 {
        return "";
    }
    // A single join (suffix after every entry) avoids the quadratic cost of
    // repeated `+=` concatenation when serialising large messages.
    string suffix = clonedSchema.delimiters.segment == "\n" ? "" : "\n";
    return string:'join(suffix, ...ediText) + suffix;
}

# Creates an EDI schema from a string or a JSON.
#
# + schema - Schema of the EDI type 
# + return - Error is returned if the given schema is not valid
public isolated function getSchema(string|json schema) returns EdiSchema|error {
    if !(schema is map<json> || schema is string) {
        return error("Schema is not valid.");
    }
    json schemaJson;
    if schema is string {
        io:StringReader sr = new (schema);
        schemaJson = check sr.readJson();
    } else {
        schemaJson = schema;
    }
    // Clone schema to prevent modifying originals with references.
    json clonedSchema = check schemaJson.cloneWithType();
    check denormalizeSchema(clonedSchema);
    return clonedSchema.cloneWithType(EdiSchema);
}

# Represents EDI module related errors
public type Error distinct error;

# Represents an input EDI text that does not conform to the expected envelope structure
# (e.g. a missing or malformed envelope segment, or multiple interchanges in one call).
public type InvalidEnvelopeError distinct Error;

# Represents a schema that cannot support the requested operation
# (e.g. no `envelope` declaration, or a fixed-length "FL" schema used with envelope-aware APIs).
public type SchemaCompatibilityError distinct Error;

# Represents a refusal to serialize an `EdiInterchange`
# (e.g. a transaction `body` holds an `error` from a fail-safe parse).
public type SerializationError distinct Error;
