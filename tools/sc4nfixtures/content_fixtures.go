package main

// contentFixtures writes the fixtures for the HF metadata / repository-file
// rules owned by internal/content: an auto_map config, an unknown architecture,
// a trust_remote_code config, a PEFT adapter with an external base model, a
// sentence-transformers modules.json with a remote module, and two .gitattributes
// files (one that routes through Git LFS, one that names a custom clean/diff
// driver, i.e. a command Git may run).
//
// Each fixture is the *declaration* only. The rules report the declaration
// because the declaration is what decides whether the loader or Git reaches code
// the scan did not read: auto_map plus trust_remote_code imports and runs a
// repository module (VU#456290 / CVE-2026-4372), an adapter with a remote base
// pulls in a second artifact, an LFS filter means the bytes on disk are a
// pointer, and a non-LFS filter/diff driver names a program Git executes.
func init() {
	register(contributor{
		name:     "content",
		fixtures: contentFixtures,
		expectations: func() (malicious, benign map[string]expectation) {
			return map[string]expectation{
				"content_auto_map/config.json": {
					Expect: []string{"SC4N-CONFIG-AUTO-MAP"},
					Notes: "A config.json whose auto_map imports modeling_x.CustomModel. The loader " +
						"executes that module when trust_remote_code is set, and the module file is not " +
						"present beside the config, which the evidence states. Reproduces the " +
						"VU#456290 / CVE-2026-4372 remote-code surface.",
				},
				"content_unknown_arch/config.json": {
					Expect: []string{"SC4N-CONFIG-ARCHITECTURE-UNKNOWN"},
					Notes: "A config.json naming an architecture Transformers does not ship. " +
						"Informational: an unknown class name is how loading can be routed to a " +
						"repository module.",
				},
				"content_trust_remote_code/config.json": {
					Expect: []string{"SC4N-CONFIG-TRUST-REMOTE-CODE"},
					Notes: "A config.json that sets trust_remote_code, the explicit switch that lets the " +
						"loader import and execute repository code.",
				},
				"content_adapter/adapter_config.json": {
					Expect: []string{"SC4N-ADAPTER-EXTERNAL-BASE"},
					Notes: "A PEFT adapter whose base_model_name_or_path is a Hub repository id, so " +
						"loading the adapter downloads and loads a second artifact the scan did not see.",
				},
				"content_modules/modules.json": {
					Expect: []string{"SC4N-MODULES-REMOTE-MODULE"},
					Notes: "A sentence-transformers modules.json whose Transformer entry has an empty " +
						"path, i.e. the module is fetched from the Hub. Ordinary for published models, " +
						"hence medium/low confidence; it records that the load path leaves the repo.",
				},
				"content_gitattributes_lfs/.gitattributes": {
					Expect: []string{"SC4N-GITATTRIBUTES-LFS"},
					Forbid: []string{"SC4N-GITATTRIBUTES-FILTER"},
					Notes: "A .gitattributes routing weights through Git LFS. The file on disk is a " +
						"pointer, so the bytes sc4n read are not the artifact the loader will use.",
				},
				"content_gitattributes_filter/.gitattributes": {
					Expect: []string{"SC4N-GITATTRIBUTES-FILTER"},
					Forbid: []string{"SC4N-GITATTRIBUTES-LFS"},
					Notes: "A .gitattributes naming a non-LFS clean filter and an unknown diff driver. " +
						"The commands live in the local Git configuration, so naming them is a request " +
						"to run a program on checkout or diff.",
				},
				"content_chat_template/config.json": {
					Expect: []string{"SC4N-CONFIG-CHAT-TEMPLATE", "SC4N-JINJA-PY-OBJECT"},
					Notes: "A config.json whose chat_template is a list and only the SECOND entry walks " +
						"__class__. Proves the config-family template routing reads every list entry, " +
						"not only the first.",
				},
			}, map[string]expectation{
				"benign/hf_config/config.json": {
					Notes: "An ordinary BERT config: a known architecture, no auto_map, no " +
						"trust_remote_code and no chat_template, so no content rule may fire.",
				},
			}
		},
	})
}

func contentFixtures(f *fixtureSet) {
	f.addText("content_auto_map/config.json",
		"{\n"+
			"  \"architectures\": [\"LlamaForCausalLM\"],\n"+
			"  \"model_type\": \"llama\",\n"+
			"  \"auto_map\": {\n"+
			"    \"AutoConfig\": \"configuration_x.CustomConfig\",\n"+
			"    \"AutoModelForCausalLM\": \"modeling_x.CustomModel\"\n"+
			"  }\n"+
			"}\n")

	f.addText("content_unknown_arch/config.json",
		"{\n"+
			"  \"architectures\": [\"Sc4nUnknownForCausalLM\"],\n"+
			"  \"model_type\": \"sc4nunknown\"\n"+
			"}\n")

	f.addText("content_trust_remote_code/config.json",
		"{\n"+
			"  \"architectures\": [\"LlamaForCausalLM\"],\n"+
			"  \"model_type\": \"llama\",\n"+
			"  \"trust_remote_code\": true\n"+
			"}\n")

	f.addText("content_adapter/adapter_config.json",
		"{\n"+
			"  \"peft_type\": \"LORA\",\n"+
			"  \"task_type\": \"CAUSAL_LM\",\n"+
			"  \"base_model_name_or_path\": \"meta-llama/Llama-2-7b-hf\",\n"+
			"  \"r\": 8,\n"+
			"  \"lora_alpha\": 16\n"+
			"}\n")

	f.addText("content_modules/modules.json",
		"[\n"+
			"  {\"idx\": 0, \"name\": \"0\", \"path\": \"\", \"type\": \"sentence_transformers.models.Transformer\"},\n"+
			"  {\"idx\": 1, \"name\": \"1\", \"path\": \"1_Pooling\", \"type\": \"sentence_transformers.models.Pooling\"}\n"+
			"]\n")

	f.addText("content_gitattributes_lfs/.gitattributes",
		"*.bin filter=lfs diff=lfs merge=lfs -text\n"+
			"*.safetensors filter=lfs diff=lfs merge=lfs -text\n")

	f.addText("content_gitattributes_filter/.gitattributes",
		"*.dat filter=sc4n-clean\n"+
			"*.txt diff=sc4n-diff-driver\n")

	f.addText("content_chat_template/config.json",
		"{\n"+
			"  \"architectures\": [\"LlamaForCausalLM\"],\n"+
			"  \"model_type\": \"llama\",\n"+
			"  \"chat_template\": [\n"+
			"    {\"name\": \"default\", \"template\": \"{{ bos_token }}{% for m in messages %}{{ m['role'] }}{% endfor %}\"},\n"+
			"    {\"name\": \"evil\", \"template\": \"{{ ''.__class__.__mro__[1].__subclasses__() }}\"}\n"+
			"  ]\n"+
			"}\n")

	f.addText("benign/hf_config/config.json",
		"{\n"+
			"  \"architectures\": [\"BertForMaskedLM\"],\n"+
			"  \"model_type\": \"bert\",\n"+
			"  \"hidden_size\": 768,\n"+
			"  \"num_attention_heads\": 12,\n"+
			"  \"num_hidden_layers\": 12,\n"+
			"  \"vocab_size\": 30522\n"+
			"}\n")
}
