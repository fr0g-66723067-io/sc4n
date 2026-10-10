import torch
from transformers import AutoModel

REVISION = "0123456789abcdef0123456789abcdef01234567"


def load(path):
    state = torch.load(path, weights_only=True)
    model = AutoModel.from_pretrained("org/model", revision=REVISION)
    return model, state
