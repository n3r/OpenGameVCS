// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
using System;
using System.Collections.Generic;
using OpenGameVcs.Protocol.V1;
if (ProtocolConstants.ContractManifestSha256.Length != 64 || CapabilityAxesFields.ProtocolVersions != 1) Environment.Exit(1);
var axes = new CapabilityAxes { ProtocolVersions = new[] { ProtocolConstants.ProtocolVersion } };
if (axes.ProtocolVersions.Count != 1) Environment.Exit(1);
var expectedFields = 0;
foreach (var message in ProtocolDescriptors.Messages) expectedFields += message.FieldCount;
if (expectedFields != ProtocolDescriptors.Fields.Count) Environment.Exit(2);
var seen = new HashSet<(ushort, ushort)>();
foreach (var field in ProtocolDescriptors.Fields)
{
    ProtocolMessageDescriptor? owner = null;
    foreach (var message in ProtocolDescriptors.Messages) if (message.Code == field.MessageCode && message.Name == field.MessageName) owner = message;
    if (owner is null || !seen.Add((field.MessageCode, field.Number)) || field.Required != (field.Presence == "required") || ((field.Reference is not null) != field.NormalizedType.Contains("reference", StringComparison.Ordinal))) Environment.Exit(3);
}
