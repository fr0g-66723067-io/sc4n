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
				"content_binary_blob.bin": {
					Expect: []string{"SC4N-CONTENT-NOT-UTF8"},
					Forbid: []string{"SC4N-UNICODE-ANOMALY"},
					Notes: "Prose head (with a bidi override in it) then 64 KiB of a binary " +
						"pattern: the not-UTF-8 skip is reported because the artifact opens as " +
						"text, and the Unicode-shape pass is forbidden because the buffer is " +
						"half binary.",
				},
				"content_auto_map/config.json": {
					Expect: []string{"SC4N-CONFIG-AUTO-MAP"},
					Forbid: []string{"SC4N-STRING-LOADER-FLAG"},
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
				"benign/json_sniffer/vocab_like.txt": {
					Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
					Notes: "A wordpiece vocabulary: the first byte is '[', which one JSON token " +
						"accepts as an array opener. The sniff requires a complete value, so the " +
						"file stays text and no mismatch is reported for a .txt that was never JSON.",
				},
				"benign/json_sniffer/sums_like.txt": {
					Forbid: []string{"SC4N-FORMAT-EXTENSION-MISMATCH"},
					Notes: "A SHA256SUMS listing: the first byte is a digit, which one JSON token " +
						"accepts as a number. Same requirement, same reason.",
				},
				"benign/json_sniffer/one_value.json": {
					Notes: "The negative control: one complete JSON value named .json is JSON, so " +
						"requiring a complete value did not stop real JSON from being claimed.",
				},
			}
		},
	})
}

func contentFixtures(f *fixtureSet) {
	// --- a binary blob that the fallback text claim used to accept --------------
	// 256 bytes of prose (so "text with binary appended" is a reading of the
	// artifact, and the head's printable run passes the classifier), a real bidi
	// override inside that prose, then 64 KiB of a repeating binary pattern that
	// makes the buffer half printable. The skip is reported (the artifact is not
	// valid UTF-8) and the Unicode-shape pass is not run: on a half-binary buffer
	// it decodes runes out of noise. Before the gate this shape produced
	// SC4N-UNICODE-ANOMALY, and through the storage members of every torch
	// checkpoint it produced 2,875 SC4N-CONTENT-NOT-UTF8 findings.
	blob := []byte("the model card for this checkpoint is short and hides nothing here: ")
	blob = append(blob, []byte("evil\xe2\x80\xae rhs-to-lhs override, then binary follows.\n")...)
	for len(blob) < 256 {
		blob = append(blob, ' ')
	}
	for i := 0; i < 64<<10/4; i++ {
		blob = append(blob, 'a', 'b', 0, 0)
	}
	blob = append(blob, '}', '\n')
	f.add("content_binary_blob.bin", blob)

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

	// --- the JSON sniff must not accept a text file's first token -----------------
	// BERT's vocab.txt begins with "[PAD]" and a SHA256SUMS line begins with a
	// digit: both yield a valid first JSON token, and accepting one token was
	// enough to dispatch the file as JSON and report a format/extension mismatch
	// for a file that is nothing but text. The sniff now requires one complete
	// JSON value, so both stay text.
	f.addText("benign/json_sniffer/vocab_like.txt",
		"[PAD]\n[unused0]\n[CLS]\n[SEP]\n")
	f.addText("benign/json_sniffer/sums_like.txt",
		"52788bf01bf59457c3aec96e1183f0321234567890abcdef  model.safetensors\n"+
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  pytorch_model.bin\n")
	f.addText("benign/json_sniffer/one_value.json", "{\"a\":1}\n")
}
