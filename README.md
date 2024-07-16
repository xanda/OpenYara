Here's a README file for your OpenYara project:

---

# OpenYara

Welcome to OpenYara, yet another YARA rule collection. This project was developed as part of an engagement with my clients, and we believe it could benefit others as well. OpenYara is released under the 0BSD license, making it very permissive for any type of use.

## Requirements

- [YARA](https://github.com/VirusTotal/yara)

## Usage

To scan a directory with all the YARA rules:

```sh
yara -r ALL_Rule.yar /path/to/scan
```

## EnrichYara

Feel free to explore **EnrichYara**, a script that adds more context about the detected files.

### Usage

```sh
./EnrichYara.sh ALL_Rule.yar /path/to/scan
```

## Updating the YARA Rule Collection

Update the YARA rule collection with one command:

```sh
./update_rules.sh
```

## License

This project is licensed under the 0BSD License.

---

Feel free to modify or expand the README as needed!
