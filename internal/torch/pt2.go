package torch

import (
	"github.com/fr0g-66723067-io/sc4n/internal/artifact"
	"github.com/fr0g-66723067-io/sc4n/internal/source"
)

// pt2Parser handles the .pt2 export archive.
//
// The member walk is delegated exactly as for the new-format zip: the archive
// layer dispatches each member through artifact.ScanMember, so
// data/sample_inputs/*.pt recurse into this package (they are ordinary torch.save
// zips) and data/constants/custom_obj_* reach the pickle engine, both without any
// special-casing here. A *.wrapper.so member is native code and is reported by
// the archive layer as SC4N-ARCHIVE-NATIVE-MEMBER, which this package must not
// duplicate.
type pt2Parser struct{}

func (pt2Parser) Parse(ctx *artifact.Ctx, s source.Source) error {
	ctx.Sink.Emit(ruleTorchPT2, 0,
		".pt2 export archive: sample_inputs/*.pt and constants/custom_obj_* are torch.save pickles")
	return parseZipLike(ctx, s)
}

func init() {
	artifact.RegisterFormat(artifact.Info{
		Format:    artifact.FormatPT2,
		Magic:     "PK\\x03\\x04 (member archive_format)",
		Depth:     artifact.DepthDeep,
		Container: true,
		Notes: "members are dispatched by content: data/sample_inputs/*.pt are real torch.save pickles, " +
			"data/constants/custom_obj_* are TorchBind objects (pickles), and a *.wrapper.so member is " +
			"reported as SC4N-ARCHIVE-NATIVE-MEMBER.",
	})
	artifact.RegisterParser(artifact.FormatPT2, pt2Parser{})
}
