# FlagEmbedding

Fine-tuning examples live at com/FlagOpen/FlagEmbedding/tree/master/examples/finetune in the repository.

## Usage

```python
from transformers import AutoModel
model = AutoModel.from_pretrained('BAAI/bge-base-en-v1.5')
model.eval()
```
