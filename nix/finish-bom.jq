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

(if .metadata.component then .metadata.component |= finish else . end)
| (if .components then .components |= map(finish) else . end)
| if any(.. | objects; (.name? // "") == "bombon:manufacturer-url") then
    error("A bombon:manufacturer-url property is left in the SBOM")
  else
    .
  end
