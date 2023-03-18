package devsecops

exceptions = ["CVE-2007-2379", "CVE-2007-2372"]

block = true {
 vulnerability = input.matches[_].vulnerability
 vulnerability.severity = "Critical"
 not contains(exceptions, vulnerability.id)
}

contains(vulnerabilities, elem) {
  vulnerabilities[_] = elem
}