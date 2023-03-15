rule royal_ransomware{
    Author: Fevar54
    meta:
        description = "Detects Royal ransomware's use of BlackCat encryption implementation."
    strings:
        $blackcat = "BlackCat"
    condition:
        all of them and
        $blackcat
}
