package engineflags

import "fmt"

func NucleiArgs(targetsFile, templates, proxy, errorFile string, rate, timeout int) []string {
	return []string{"-l", targetsFile, "-t", templates, "-pt", "http", "-ept", "code,headless,javascript,dns,tcp,ssl,file,websocket,whois,workflow", "-dr", "-fhr", "-duc", "-ni", "-nh", "-no-stdin", "-jsonl", "-silent", "-omit-raw", "-omit-template", "-rl", fmt.Sprint(rate), "-c", "1", "-bs", "1", "-mhe", "3", "-retries", "0", "-timeout", fmt.Sprint(timeout), "-rsr", "2097152", "-p", proxy, "-pi", "-elog", errorFile}
}

func TrivyArgs(kind, input, cache, output string) []string {
	command := "filesystem"
	if kind == "image-archive" {
		command = "image"
	} else if kind == "rootfs" || kind == "artifact" {
		command = "rootfs"
	}
	args := []string{command, "--cache-dir", cache, "--config", "", "--ignorefile", "", "--scanners", "vuln", "--format", "json", "--output", output, "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check", "--disable-telemetry", "--skip-vex-repo-update", "--no-progress", "--timeout", "10m"}
	if kind == "rootfs" {
		args = append(args, "--pkg-types", "os")
	} else if kind == "artifact" {
		// The selected ELF files keep private non-executable permissions. Force
		// the Go parser without granting execute permission or running them.
		args = append(args, "--pkg-types", "library", "--file-patterns", "gobinary:.*")
	}
	if kind == "image-archive" {
		args = append(args, "--input", input)
	} else {
		args = append(args, input)
	}
	return args
}

func ZAPArgs(jar, home, plan string) []string {
	return []string{"-Xmx512m", "-Djava.awt.headless=true", "-jar", jar, "-cmd", "-silent", "-notel", "-host", "127.0.0.1", "-port", "0", "-dir", home, "-autorun", plan}
}
func TrivyDownloadArgs(cache string) []string {
	return []string{"image", "--cache-dir", cache, "--config", "", "--download-db-only", "--skip-version-check", "--disable-telemetry", "--no-progress"}
}

func TrivyDownloadJavaArgs(cache string) []string {
	return []string{"image", "--cache-dir", cache, "--config", "", "--download-java-db-only", "--skip-version-check", "--disable-telemetry", "--no-progress"}
}
