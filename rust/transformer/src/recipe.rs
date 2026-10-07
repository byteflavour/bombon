use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// A build recipe, i.e. the content of a `.drv` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    pub outputs: Vec<Output>,
    pub input_recipes: Vec<String>,
    pub input_sources: Vec<String>,
    pub env: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub name: String,
    pub path: String,
    pub hash_algorithm: String,
    pub hash: String,
}

impl Recipe {
    /// Parse the text of a `.drv` file.
    ///
    /// A `.drv` file is a single term of the form
    /// `Derive(outputs, inputDrvs, inputSrcs, system, builder, args, env)`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut parser = Parser::new(text);

        parser.expect_str("Derive(")?;
        let outputs = parser.list(|p| {
            p.expect('(')?;
            let name = p.string()?;
            p.expect(',')?;
            let path = p.string()?;
            p.expect(',')?;
            let hash_algorithm = p.string()?;
            p.expect(',')?;
            let hash = p.string()?;
            p.expect(')')?;
            Ok(Output {
                name,
                path,
                hash_algorithm,
                hash,
            })
        })?;
        parser.expect(',')?;
        let input_recipes = parser.list(|p| {
            p.expect('(')?;
            let path = p.string()?;
            p.expect(',')?;
            p.list(Parser::string)?;
            p.expect(')')?;
            Ok(path)
        })?;
        parser.expect(',')?;
        let input_sources = parser.list(Parser::string)?;
        parser.expect(',')?;
        // The system, the builder and its arguments are not needed.
        parser.string()?;
        parser.expect(',')?;
        parser.string()?;
        parser.expect(',')?;
        parser.list(Parser::string)?;
        parser.expect(',')?;
        let plain_env = parser.list(|p| {
            p.expect('(')?;
            let key = p.string()?;
            p.expect(',')?;
            let value = p.string()?;
            p.expect(')')?;
            Ok((key, value))
        })?;
        parser.expect(')')?;
        parser.end()?;

        let mut env = BTreeMap::new();
        for (key, value) in plain_env {
            // With structured attributes, the attributes of the derivation are stored as JSON.
            if key == "__json" {
                let attrs: BTreeMap<String, Value> = serde_json::from_str(&value)
                    .context("Failed to parse the structured attributes")?;
                env.extend(attrs);
            } else {
                env.entry(key).or_insert(Value::String(value));
            }
        }

        Ok(Self {
            outputs,
            input_recipes,
            input_sources,
            env,
        })
    }

    /// The value of an attribute that is a non-empty string.
    fn string(&self, key: &str) -> Option<String> {
        self.env
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    }

    /// The value of an attribute that is a list of strings.
    ///
    /// Without structured attributes, lists are stored as a whitespace separated string.
    fn list(&self, key: &str) -> Vec<String> {
        match self.env.get(key) {
            Some(Value::String(s)) => s.split_whitespace().map(ToOwned::to_owned).collect(),
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }
}

struct Parser<'a> {
    rest: &'a str,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self { rest: text }
    }

    fn expect(&mut self, expected: char) -> Result<()> {
        match self.rest.strip_prefix(expected) {
            Some(rest) => {
                self.rest = rest;
                Ok(())
            }
            None => bail!("Expected '{expected}' but found {}", self.found()),
        }
    }

    fn expect_str(&mut self, expected: &str) -> Result<()> {
        match self.rest.strip_prefix(expected) {
            Some(rest) => {
                self.rest = rest;
                Ok(())
            }
            None => bail!("Expected '{expected}' but found {}", self.found()),
        }
    }

    fn end(&self) -> Result<()> {
        if !self.rest.trim_end().is_empty() {
            bail!("Expected the end of the recipe but found {}", self.found());
        }
        Ok(())
    }

    /// A short description of what comes next, for error messages.
    fn found(&self) -> String {
        if self.rest.is_empty() {
            "the end of the recipe".into()
        } else {
            format!("'{}'", self.rest.chars().take(16).collect::<String>())
        }
    }

    fn string(&mut self) -> Result<String> {
        self.expect('"')?;
        let mut value = String::new();
        let mut chars = self.rest.char_indices();
        while let Some((index, c)) = chars.next() {
            match c {
                '"' => {
                    self.rest = &self.rest[index + 1..];
                    return Ok(value);
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => value.push('\n'),
                    Some((_, 'r')) => value.push('\r'),
                    Some((_, 't')) => value.push('\t'),
                    Some((_, escaped)) => value.push(escaped),
                    None => break,
                },
                _ => value.push(c),
            }
        }
        bail!("Unterminated string")
    }

    fn list<T>(&mut self, mut item: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        self.expect('[')?;
        let mut items = Vec::new();
        if self.rest.starts_with(']') {
            self.expect(']')?;
            return Ok(items);
        }
        loop {
            items.push(item(self)?);
            if self.rest.starts_with(',') {
                self.expect(',')?;
            } else {
                self.expect(']')?;
                return Ok(items);
            }
        }
    }
}

/// What a recipe states about one of its outputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecipeOutput {
    /// The store path of the recipe.
    pub recipe: String,
    /// The name of the output, e.g. `out` or `dev`.
    pub output: String,
    pub name: Option<String>,
    pub pname: Option<String>,
    pub version: Option<String>,
    pub patches: Vec<String>,
    /// The store path of the source the recipe builds from.
    pub src: Option<String>,
    /// The URLs the recipe downloads its output from.
    pub urls: Vec<String>,
    /// Set if the content of the output is fixed by a hash.
    pub fixed: Option<FixedOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedOutput {
    pub algorithm: String,
    /// Whether the hash is over a serialisation of a file tree instead of over a single file.
    pub recursive: bool,
    /// The hex encoded digest.
    pub digest: String,
}

impl RecipeOutput {
    /// Whether the output is downloaded instead of built.
    pub fn is_download(&self) -> bool {
        self.fixed.is_some() && !self.urls.is_empty()
    }
}

/// The outputs of all recipes of a build closure, indexed by their store path.
#[derive(Debug, Clone, Default)]
pub struct RecipeIndex(BTreeMap<String, RecipeOutput>);

impl RecipeIndex {
    /// Read a JSON file that maps the store paths of recipes to their text.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let recipes: BTreeMap<String, String> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse recipes at {}", path.display()))?;
        Self::from_recipes(&recipes)
    }

    pub fn from_recipes(recipes: &BTreeMap<String, String>) -> Result<Self> {
        let mut index = BTreeMap::new();
        // Recipes are visited in the order of their store path. If multiple recipes produce the
        // same output, the first one is kept so that the result is reproducible.
        for (recipe_path, text) in recipes {
            let recipe = Recipe::parse(text)
                .with_context(|| format!("Failed to parse recipe {recipe_path}"))?;
            let mut urls = recipe.list("urls");
            if urls.is_empty() {
                urls = recipe.list("url");
            }
            for output in &recipe.outputs {
                // The path of an output is only known in advance if it is not content addressed.
                if output.path.is_empty() {
                    continue;
                }
                let fixed = (!output.hash.is_empty()).then(|| {
                    let (recursive, algorithm) = match output.hash_algorithm.strip_prefix("r:") {
                        Some(algorithm) => (true, algorithm),
                        None => (false, output.hash_algorithm.as_str()),
                    };
                    FixedOutput {
                        algorithm: algorithm.to_string(),
                        recursive,
                        digest: output.hash.clone(),
                    }
                });
                index
                    .entry(output.path.clone())
                    .or_insert_with(|| RecipeOutput {
                        recipe: recipe_path.clone(),
                        output: output.name.clone(),
                        name: recipe.string("name"),
                        pname: recipe.string("pname"),
                        version: recipe.string("version"),
                        patches: recipe.list("patches"),
                        src: recipe.string("src"),
                        urls: urls.clone(),
                        fixed,
                    });
            }
        }
        Ok(Self(index))
    }

    pub fn get(&self, store_path: &str) -> Option<&RecipeOutput> {
        self.0.get(store_path)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A package with multiple outputs and a patch.
    pub const LIBSSH2: &str = r#"Derive([("dev","/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev","",""),("devdoc","/nix/store/w3zqikpwcvzxj1mczkna43bx12zr6kvj-libssh2-1.11.1-devdoc","",""),("out","/nix/store/w5lmwpf3abphzw1wcfy40a3sb2djw9gl-libssh2-1.11.1","","")],[("/nix/store/8pf3wji6hg6mh5pfch4g5qai0brcxkii-openssl-3.6.2.drv",["dev"]),("/nix/store/92yhjpd6g9n92dxn52xv2f29h55g6n4z-zlib-1.3.2.drv",["dev"]),("/nix/store/g7p7rs03xah2w00a142hzas9h4fkwpck-bash-5.3p9.drv",["out"]),("/nix/store/l0x59a9gpwqh6rxxx2sxbl5nd72r4bc8-stdenv-linux.drv",["out"]),("/nix/store/l4q7jsk9n0ys3qb31zafgzwakpwq0360-libssh2-1.11.1.tar.gz.drv",["out"])],["/nix/store/l622p70vy8k5sh7y5wizi5f2mic6ynpg-source-stdenv.sh","/nix/store/m9171q7kn5bbp08hqmhfra41mmn6p5nk-CVE-2026-7598.patch","/nix/store/shkw4qm9qcw5sc5n1k5jznc83ny02r39-default-builder.sh"],"x86_64-linux","/nix/store/zh1ijdhb6gng1509b1zrilb6xlzx60j6-bash-5.3p9/bin/bash",["-e","/nix/store/l622p70vy8k5sh7y5wizi5f2mic6ynpg-source-stdenv.sh","/nix/store/shkw4qm9qcw5sc5n1k5jznc83ny02r39-default-builder.sh"],[("__structuredAttrs",""),("buildInputs","/nix/store/a9psmsc93llkravrd50rrv8k3dwdw60x-zlib-1.3.2-dev"),("builder","/nix/store/zh1ijdhb6gng1509b1zrilb6xlzx60j6-bash-5.3p9/bin/bash"),("cmakeFlags",""),("configureFlags",""),("depsBuildBuild",""),("depsBuildBuildPropagated",""),("depsBuildTarget",""),("depsBuildTargetPropagated",""),("depsHostHost",""),("depsHostHostPropagated",""),("depsTargetTarget",""),("depsTargetTargetPropagated",""),("dev","/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev"),("devdoc","/nix/store/w3zqikpwcvzxj1mczkna43bx12zr6kvj-libssh2-1.11.1-devdoc"),("doCheck",""),("doInstallCheck",""),("mesonFlags",""),("name","libssh2-1.11.1"),("nativeBuildInputs",""),("out","/nix/store/w5lmwpf3abphzw1wcfy40a3sb2djw9gl-libssh2-1.11.1"),("outputs","out dev devdoc"),("patches","/nix/store/m9171q7kn5bbp08hqmhfra41mmn6p5nk-CVE-2026-7598.patch"),("pname","libssh2"),("postPatch","substituteInPlace ./config.guess --replace-fail /usr/bin/uname uname\n"),("propagatedBuildInputs","/nix/store/a8jlbhcp8p38gz1lfxrkrb6359ksc9fx-openssl-3.6.2-dev"),("propagatedNativeBuildInputs",""),("src","/nix/store/j04yfblg6sk5abb4n067xv0x0dfraf73-libssh2-1.11.1.tar.gz"),("stdenv","/nix/store/xknwpg5yjxxsffmwdmpys269543wpdy5-stdenv-linux"),("strictDeps",""),("system","x86_64-linux"),("version","1.11.1")])"#;

    /// A package that uses structured attributes.
    pub const HELLO: &str = r#"Derive([("out","/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3","","")],[("/nix/store/9w4h6mwgy4vivksdb54jhz6i2dihqv1l-hello-2.12.3.tar.gz.drv",["out"]),("/nix/store/g7p7rs03xah2w00a142hzas9h4fkwpck-bash-5.3p9.drv",["out"]),("/nix/store/i1fmvnw4pqbjhcygp8rggs6n88jg1bny-version-check-hook.drv",["out"]),("/nix/store/l0x59a9gpwqh6rxxx2sxbl5nd72r4bc8-stdenv-linux.drv",["out"])],["/nix/store/l622p70vy8k5sh7y5wizi5f2mic6ynpg-source-stdenv.sh","/nix/store/shkw4qm9qcw5sc5n1k5jznc83ny02r39-default-builder.sh"],"x86_64-linux","/nix/store/zh1ijdhb6gng1509b1zrilb6xlzx60j6-bash-5.3p9/bin/bash",["-e","/nix/store/l622p70vy8k5sh7y5wizi5f2mic6ynpg-source-stdenv.sh","/nix/store/shkw4qm9qcw5sc5n1k5jznc83ny02r39-default-builder.sh"],[("__json","{\"NIX_MAIN_PROGRAM\":\"hello\",\"buildInputs\":[],\"builder\":\"/nix/store/zh1ijdhb6gng1509b1zrilb6xlzx60j6-bash-5.3p9/bin/bash\",\"cmakeFlags\":[],\"configureFlags\":[],\"depsBuildBuild\":[],\"depsBuildBuildPropagated\":[],\"depsBuildTarget\":[],\"depsBuildTargetPropagated\":[],\"depsHostHost\":[],\"depsHostHostPropagated\":[],\"depsTargetTarget\":[],\"depsTargetTargetPropagated\":[],\"doCheck\":true,\"doInstallCheck\":true,\"env\":{\"NIX_MAIN_PROGRAM\":\"hello\"},\"mesonFlags\":[],\"name\":\"hello-2.12.3\",\"nativeBuildInputs\":[\"/nix/store/n1p1y0pnxhh7qb16g4avkr7hhb17w7yj-version-check-hook\"],\"outputChecks\":{\"out\":{}},\"outputs\":[\"out\"],\"patches\":[],\"pname\":\"hello\",\"postInstallCheck\":\"stat \\\"${!outputBin}/bin/hello\\\"\\n\",\"propagatedBuildInputs\":[],\"propagatedNativeBuildInputs\":[],\"src\":\"/nix/store/wj7phsmi7ncidl8k00p489krqss7n9sd-hello-2.12.3.tar.gz\",\"stdenv\":\"/nix/store/xknwpg5yjxxsffmwdmpys269543wpdy5-stdenv-linux\",\"strictDeps\":false,\"system\":\"x86_64-linux\",\"version\":\"2.12.3\"}"),("out","/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3")])"#;

    /// The download of a single file.
    pub const XZ_TARBALL: &str = r#"Derive([("out","/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz","sha256","3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0")],[],[],"builtin","builtin:fetchurl",[],[("builder","builtin:fetchurl"),("executable",""),("impureEnvVars","http_proxy https_proxy ftp_proxy all_proxy no_proxy"),("name","xz-5.8.3.tar.gz"),("out","/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz"),("outputHash","sha256-PToblzryGBFPT4ibuqL0wDfequDI6BXuw4HD1Ua5dKA="),("outputHashAlgo",""),("outputHashMode","flat"),("preferLocalBuild","1"),("system","builtin"),("unpack",""),("url","https://tukaani.org/xz/xz-5.8.3.tar.gz"),("urls","https://tukaani.org/xz/xz-5.8.3.tar.gz")])"#;

    #[test]
    fn parse_outputs_and_inputs() -> Result<()> {
        let recipe = Recipe::parse(LIBSSH2)?;

        assert_eq!(
            recipe
                .outputs
                .iter()
                .map(|o| o.name.as_str())
                .collect::<Vec<_>>(),
            ["dev", "devdoc", "out"]
        );
        assert_eq!(
            recipe.outputs[2].path,
            "/nix/store/w5lmwpf3abphzw1wcfy40a3sb2djw9gl-libssh2-1.11.1"
        );
        assert_eq!(recipe.input_recipes.len(), 5);
        assert_eq!(recipe.input_sources.len(), 3);
        assert_eq!(recipe.string("pname").as_deref(), Some("libssh2"));
        assert_eq!(recipe.string("version").as_deref(), Some("1.11.1"));
        assert_eq!(
            recipe.list("patches"),
            ["/nix/store/m9171q7kn5bbp08hqmhfra41mmn6p5nk-CVE-2026-7598.patch"]
        );
        // Escape sequences are resolved.
        assert!(
            recipe
                .string("postPatch")
                .is_some_and(|s| s.ends_with("uname\n"))
        );
        Ok(())
    }

    #[test]
    fn parse_fixed_output() -> Result<()> {
        let recipe = Recipe::parse(XZ_TARBALL)?;

        assert_eq!(recipe.outputs[0].hash_algorithm, "sha256");
        assert_eq!(
            recipe.outputs[0].hash,
            "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0"
        );
        assert_eq!(
            recipe.list("urls"),
            ["https://tukaani.org/xz/xz-5.8.3.tar.gz"]
        );
        assert_eq!(recipe.string("pname"), None);
        Ok(())
    }

    #[test]
    fn parse_structured_attributes() -> Result<()> {
        let recipe = Recipe::parse(HELLO)?;

        assert_eq!(recipe.string("pname").as_deref(), Some("hello"));
        assert_eq!(recipe.string("version").as_deref(), Some("2.12.3"));
        assert_eq!(
            recipe.string("src").as_deref(),
            Some("/nix/store/wj7phsmi7ncidl8k00p489krqss7n9sd-hello-2.12.3.tar.gz")
        );
        assert!(recipe.list("patches").is_empty());
        Ok(())
    }

    #[test]
    fn parse_rejects_malformed_recipes() {
        // Truncated.
        assert!(Recipe::parse(&XZ_TARBALL[..XZ_TARBALL.len() - 2]).is_err());
        assert!(Recipe::parse(&LIBSSH2[..200]).is_err());
        assert!(Recipe::parse("").is_err());
        // Trailing content.
        assert!(Recipe::parse(&format!("{XZ_TARBALL}[]")).is_err());
        // Not a `Derive` term.
        assert!(Recipe::parse(&XZ_TARBALL.replacen("Derive(", "DrvWithVersion(", 1)).is_err());
        // Invalid structured attributes.
        assert!(Recipe::parse(&HELLO.replacen("{\\\"NIX_MAIN_PROGRAM\\\"", "{", 1)).is_err());
    }

    #[test]
    fn index_recipes() -> Result<()> {
        let recipes = BTreeMap::from([
            ("/nix/store/b-libssh2.drv".to_string(), LIBSSH2.to_string()),
            ("/nix/store/c-xz.drv".to_string(), XZ_TARBALL.to_string()),
            // Another recipe that downloads the same file from somewhere else.
            (
                "/nix/store/a-xz.drv".to_string(),
                XZ_TARBALL.replace("tukaani.org", "example.org"),
            ),
            // An output whose path is not known in advance.
            (
                "/nix/store/d-floating.drv".to_string(),
                HELLO.replace(
                    "/nix/store/nm7p8wxflggcwxfzayhysq4z6a1wg373-hello-2.12.3",
                    "",
                ),
            ),
        ]);
        let index = RecipeIndex::from_recipes(&recipes)?;

        assert_eq!(index.0.len(), 4);

        let dev = index
            .get("/nix/store/b6dac7q3270fhwxr0glxi35hrhw2v97r-libssh2-1.11.1-dev")
            .context("Missing output")?;
        assert_eq!(dev.output, "dev");
        assert_eq!(dev.recipe, "/nix/store/b-libssh2.drv");
        assert_eq!(dev.pname.as_deref(), Some("libssh2"));
        assert_eq!(dev.fixed, None);
        assert!(!dev.is_download());

        let tarball = index
            .get("/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz")
            .context("Missing output")?;
        assert!(tarball.is_download());
        // The recipe with the smallest store path wins.
        assert_eq!(tarball.urls, ["https://example.org/xz/xz-5.8.3.tar.gz"]);
        assert_eq!(
            tarball.fixed,
            Some(FixedOutput {
                algorithm: "sha256".into(),
                recursive: false,
                digest: "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0".into(),
            })
        );
        Ok(())
    }

    #[test]
    fn index_recursive_hash() -> Result<()> {
        let recipes = BTreeMap::from([(
            "/nix/store/a-source.drv".to_string(),
            XZ_TARBALL.replace("\"sha256\"", "\"r:sha256\""),
        )]);
        let index = RecipeIndex::from_recipes(&recipes)?;

        let output = index
            .get("/nix/store/lih1c5qn71i56blnj7bq7jhnm3k1z4q9-xz-5.8.3.tar.gz")
            .context("Missing output")?;
        assert!(output.fixed.as_ref().is_some_and(|f| f.recursive));
        Ok(())
    }

    #[test]
    fn index_names_the_recipe_that_fails_to_parse() {
        let recipes = BTreeMap::from([("/nix/store/a-broken.drv".to_string(), "Derive(".into())]);

        let error = RecipeIndex::from_recipes(&recipes)
            .err()
            .map(|e| format!("{e:#}"));
        assert!(error.is_some_and(|e| e.contains("/nix/store/a-broken.drv")));
    }
}
