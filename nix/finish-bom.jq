# Finishes the SBOM after it has been converted to the final CycloneDX version.
#
# The transformer writes CycloneDX v1.5. What only exists in later versions is passed along in
# properties and moved to where it belongs here. Such a property is never part of the final SBOM:
# if it cannot be moved, the SBOM is not generated.

# The creator of a component, see BSI TR-03183-2 section 5.2.2. `manufacturer` only exists on a
# component since CycloneDX v1.6.
def manufacturer:
  (.properties // []) as $properties
  | ($properties | map(select(.name == "bombon:manufacturer-url") | .value)) as $urls
  | if ($urls | length) == 0 then
      .
    elif ($urls | length) > 1 or ($urls[0] | type) != "string" or ($urls[0] | length) == 0 then
      error("Cannot turn bombon:manufacturer-url of \(."bom-ref" // .name) into a manufacturer")
    else
      .manufacturer = { url: $urls }
      | .properties = ($properties | map(select(.name != "bombon:manufacturer-url")))
      | if (.properties | length) == 0 then del(.properties) else . end
    end;

def finish: manufacturer;

# Who created something, see BSI TR-03183-2 sections 5.2.1 and 5.2.2: an email address or a URL
# and optionally a name.
def creator:
  { name, url: (if .url then [ .url ] else null end), contact: (if .email then [ { email } ] else null end) }
  | with_entries(select(.value != null));

# A date and time in UTC that exists.
def timestamp:
  . as $timestamp
  | if (try (strptime("%Y-%m-%dT%H:%M:%SZ") | mktime | todate) catch null) == $timestamp then
      $timestamp
    else
      error("timestamp: \($timestamp) is not a date and time in UTC")
    end;

# What the caller says about the SBOM and its subject.
($options[0] // {}) as $given
| (if .metadata.component then .metadata.component |= finish else . end)
| (if .components then .components |= map(finish) else . end)
| if any(.. | objects; (.name? // "") == "bombon:manufacturer-url") then
    error("A bombon:manufacturer-url property is left in the SBOM")
  else
    .
  end
| (if $given.timestamp then .metadata.timestamp = ($given.timestamp | timestamp) else . end)
| (if $given.creator then .metadata.manufacturer = ($given.creator | creator) else . end)
| (if $given.subject.creator then .metadata.component.manufacturer = ($given.subject.creator | creator) else . end)
