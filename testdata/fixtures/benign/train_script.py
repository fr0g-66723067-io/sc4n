from transformers import AutoModel, AutoTokenizer

def build(cfg):
    model_name = cfg.model_name
    model = AutoModel.from_pretrained(model_name)
    tok = AutoTokenizer.from_pretrained(model_name)
    return model, tok
