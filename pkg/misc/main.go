package main

import (
	"fmt"
	"github.com/Masterminds/semver"
	"log"
	"regexp"
)

func main() {
	// Example versions
	versionStr1 := "2.38-r11"
	versionStr2 := "v2.39.0"

	// Get constraints (which are actually just versions in this case)
	constraint1, err := parseVersionToSemver(versionStr1)
	if err != nil {
		log.Fatalf("Error getting constraint for version 1: %v", err)
	}
	constraint2, err := parseVersionToSemver(versionStr2)
	if err != nil {
		log.Fatalf("Error getting constraint for version 2: %v", err)
	}

	fmt.Printf("Constraint 1: %s\n", constraint1)
	fmt.Printf("Constraint 2: %s\n", constraint2)

	// Parse versions
	v1, err := semver.NewVersion(constraint1)
	if err != nil {
		log.Fatalf("Error parsing version 1: %v", err)
	}
	v2, err := semver.NewVersion(constraint2)
	if err != nil {
		log.Fatalf("Error parsing version 2: %v", err)
	}

	// Compare versions
	comparison := v1.Compare(v2)
	if comparison < 0 {
		fmt.Println("Version 1 is lesser than Version 2")
	} else if comparison > 0 {
		fmt.Println("Version 1 is greater than Version 2")
	} else {
		fmt.Println("Version 1 is equal to Version 2")
	}
}

func parseVersionToSemver(version string) (string, error) {
	if isSemver(version) {
		semver, _, _, _, _, _, err := parseSemver(version)
		if err != nil {
			return "", fmt.Errorf("unable to parse semver: %v", err)
		}
		return semver, nil
	} else if almostSemVer(version) {
		s, err := fixAlmostSemVer(version)
		if err != nil {
			return "", err
		}
		return s, nil
	}

	return version, nil
}

func fixAlmostSemVer(s string) (string, error) {
	matches := almostExactSvR.FindStringSubmatch(s)
	if len(matches) == 0 {
		return "", fmt.Errorf("Did not match AlmostSemVer: %q", s)
	}
	return fmt.Sprintf("%s-%s", matches[almostExactSvR.SubexpIndex("beforerel")], matches[almostExactSvR.SubexpIndex("afterrel")]), nil
}

func almostSemVer(s string) bool {
	return !exactSvR.MatchString(s) && almostExactSvR.MatchString(s)
}

// check for exac semvers
var exactSvR = regexp.MustCompile(`^v?(?P<semver>(?P<major>0|[1-9]\d*)(\.(?P<minor>0|[1-9]\d*))?(\.(?P<patch>0|[1-9]\d*))?(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$`)

// for bad semvers like v1.0.0rc8 that don't include prerelease dashes
var almostExactSvR = regexp.MustCompile(`^v?(?P<beforerel>(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*))(?P<afterrel>(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?)$`)

func isSemver(s string) bool {
	return exactSvR.MatchString(s)
}

func parseSemver(s string) (semver, major, minor, patch, prerelease, metadata string, err error) {
	return parseSemverHelper(exactSvR, s)
}

func parseSemverHelper(re *regexp.Regexp, s string) (semver, major, minor, patch, prerelease, metadata string, err error) {
	matches := re.FindStringSubmatch(s)

	if len(matches) == 0 {
		err = fmt.Errorf("did not match regex: %q %s", s, re)
		return
	}
	semverIdx := re.SubexpIndex("semver")
	majorIdx := re.SubexpIndex("major")
	minorIdx := re.SubexpIndex("minor")
	patchIdx := re.SubexpIndex("patch")
	prereleaseIdx := re.SubexpIndex("prerelease")
	metadataIdx := re.SubexpIndex("metadata")

	if semverIdx < 0 {
		err = fmt.Errorf("unable to find semver")
		return
	}

	semver = matches[re.SubexpIndex("semver")]
	if semver == "" {
		err = fmt.Errorf("unable to find semver")
		return
	}

	if majorIdx < 0 {
		major = "0"
	} else {
		major = matches[majorIdx]
	}

	if minorIdx < 0 {
		minor = "0"
	} else {
		minor = matches[minorIdx]
		if minor == "" {
			minor = "0"
		}
	}

	if patchIdx < 0 {
		patch = "0"
	} else {
		patch = matches[patchIdx]
		if patch == "" {
			patch = "0"
		}
	}

	if prereleaseIdx < 0 {
		prerelease = ""
	} else {
		prerelease = matches[prereleaseIdx]
	}

	if metadataIdx < 0 {
		metadata = ""
	} else {
		metadata = matches[metadataIdx]
	}
	return
}
