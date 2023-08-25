package kubernetes.validating.vul

import data.vul

deny[msg] {
    not vul.ignore
    msg := "image forbidden"
}
