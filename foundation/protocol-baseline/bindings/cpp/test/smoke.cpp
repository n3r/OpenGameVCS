// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
#include <opengamevcs/protocol/v1/types.hpp>
#include <cstring>
int main() {
  using namespace opengamevcs::protocol::v1;
  CapabilityAxes axes{};
  axes.protocolVersions.push_back(protocol_version);
  if (axes.protocolVersions.size() != 1 || assignments::capability_axes::protocol_versions != 1 || std::strlen(contract_manifest_sha256) != 64) return 1;
  std::size_t expected_fields = 0;
  for (const auto& message : message_descriptors) expected_fields += message.field_count;
  if (expected_fields != field_descriptors.size()) return 2;
  for (std::size_t index = 0; index < field_descriptors.size(); ++index) {
    const auto& field = field_descriptors[index];
    bool message_found = false;
    for (const auto& message : message_descriptors) if (message.code == field.message_code && std::strcmp(message.name, field.message_name) == 0) message_found = true;
    if (!message_found || field.required != (std::strcmp(field.presence, "required") == 0) || ((field.reference != nullptr) != (std::strstr(field.normalized_type, "reference") != nullptr))) return 3;
    for (std::size_t prior = 0; prior < index; ++prior) if (field_descriptors[prior].message_code == field.message_code && field_descriptors[prior].number == field.number) return 4;
  }
  return 0;
}
