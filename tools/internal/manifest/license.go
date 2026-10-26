package manifest

// OSI-approved or FSF-free SPDX ids. Not exhaustive; add ids as apps need them.
var freeLicenses = map[string]bool{}

func init() {
	for _, id := range []string{
		"0BSD", "AFL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0",
		"APSL-2.0", "Artistic-2.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-2-Clause-Patent",
		"BSD-3-Clause", "BSD-3-Clause-Clear", "BSL-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "CC0-1.0",
		"CDDL-1.0", "CECILL-2.1", "CPL-1.0", "ECL-2.0", "EFL-2.0", "EPL-1.0", "EPL-2.0",
		"EUPL-1.1", "EUPL-1.2", "FTL", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
		"GPL-3.0-or-later", "HPND", "IJG", "Imlib2", "ImageMagick", "Intel", "IPA", "ISC",
		"LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
		"LGPL-3.0-only", "LGPL-3.0-or-later", "LPL-1.02", "LPPL-1.3c", "MIT", "MIT-0",
		"MPL-1.1", "MPL-2.0", "MS-PL", "MS-RL", "MulanPSL-2.0", "NCSA", "Nokia", "OFL-1.1",
		"OpenSSL", "OSL-3.0", "PHP-3.01", "PostgreSQL", "Python-2.0", "QPL-1.0", "Ruby",
		"SISSL", "SMLNJ", "Sleepycat", "SPL-1.0", "Unicode-DFS-2016", "Unicode-3.0",
		"Unlicense", "UPL-1.0", "Vim", "W3C", "WTFPL", "X11", "XFree86-1.1", "Zlib",
		"ZPL-2.0", "ZPL-2.1",
	} {
		freeLicenses[id] = true
	}
}
