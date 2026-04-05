package evaluator

import "testing"

func TestStripJSONFences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare json",
			in:   `{"severity":"info"}`,
			want: `{"severity":"info"}`,
		},
		{
			name: "json fenced",
			in:   "```json\n{\"severity\":\"info\"}\n```",
			want: `{"severity":"info"}`,
		},
		{
			name: "plain fenced",
			in:   "```\n{\"severity\":\"info\"}\n```",
			want: `{"severity":"info"}`,
		},
		{
			name: "fenced with surrounding whitespace",
			in:   "\n   ```json\n{\"x\":1}\n```   \n",
			want: `{"x":1}`,
		},
		{
			name: "multiline json inside fence",
			in:   "```json\n{\n  \"severity\":\"critical\",\n  \"root_cause\":\"oom\"\n}\n```",
			want: "{\n  \"severity\":\"critical\",\n  \"root_cause\":\"oom\"\n}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripJSONFences(tc.in)
			if got != tc.want {
				t.Errorf("stripJSONFences(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
			}
		})
	}
}
