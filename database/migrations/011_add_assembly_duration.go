package migrations

import (
	"github.com/flashbots/mev-boost-relay/database/vars"
	migrate "github.com/rubenv/sql-migrate"
)

var Migration011AddAssemblyDuration = &migrate.Migration{
	Id: "010-add-assembly-duration",
	Up: []string{`
		ALTER TABLE ` + vars.TableBuilderBlockSubmission + ` ADD assembly_duration   bigint NOT NULL default 0;
 	`,
		``,
	},
	Down: []string{},

	DisableTransactionUp:   true,
	DisableTransactionDown: true,
}
