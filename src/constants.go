package src

var packageTypeToRegistry = map[string]string{
	"npm":          "npmjs.org",
	"golang":       "proxy.golang.org",
	"docker":       "hub.docker.com",
	"nuget":        "nuget.org",
	"pypi":         "pypi.org",
	"maven":        "repo1.maven.org",
	"packagist":    "packagist.org",
	"rubygems":     "rubygems.org",
	"cargo":        "crates.io",
	"cocoapods":    "cocoapods.org",
	"bower":        "bower.io",
	"pub":          "pub.dev",
	"cpan":         "metacpan.org",
	"alpine":       "alpine",
	"github":       "github%20actions",
	"cran":         "cran.r-project.org",
	"clojars":      "clojars.org",
	"conda":        "conda-forge.org",
	"anaconda":     "anaconda.org",
	"hackage":      "hackage.haskell.org",
	"hex":          "hex.pm",
	"julia":        "juliahub.com",
	"swift":        "swiftpackageindex.com",
	"spack":        "spack.io",
	"homebrew":     "formulae.brew.sh",
	"adelie":       "pkg.adelielinux.org",
	"puppet":       "forge.puppet.com",
	"deno":         "deno.land",
	"elm":          "package.elm-lang.org",
	"racket":       "pkgs.racket-lang.org",
	"vcpkg":        "vcpkg.io",
	"bioconductor": "bioconductor.org",
	"carthage":     "carthage",
	"postmarketos": "postmarketos",
	"elpa":         "elpa.gnu.org",
	"nongnu":       "elpa.nongnu.org",
}

const (
	sbomFlag   = "sbom"
	purlFlag   = "file"
	outputFlag = "output"
)
