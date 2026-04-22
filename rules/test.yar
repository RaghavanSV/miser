rule TestRule {
    strings:
        $a = "test_detection"
    condition:
        $a
}
