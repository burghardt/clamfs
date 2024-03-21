#!/usr/bin/env bats

@test "XML External Entity (XXE) Processing" {
    run ../src/clamfs xee-test.xml
    [[ "$status" -eq 1 ]]
    [[ "${#lines[@]}" -eq 6 ]]
    [[ "${lines[4]}" =~ "SAXParseException: Reference to external entity" ]]
}
