package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type GroupMember struct {
	User   string
	Access string
}

func (i *Index) SyncOwners(ctx context.Context, users []string, groups map[string][]GroupMember) error {
	userSet := map[string]struct{}{}
	for _, name := range users {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		userSet[name] = struct{}{}
	}
	for groupName, members := range groups {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" {
			continue
		}
		if _, exists := userSet[groupName]; exists {
			return fmt.Errorf("group name %q conflicts with user name", groupName)
		}
		for _, member := range members {
			if strings.TrimSpace(member.User) == "" {
				continue
			}
			userSet[member.User] = struct{}{}
		}
	}
	userSet["system"] = struct{}{}

	for name := range userSet {
		if _, err := i.ensureUser(ctx, name); err != nil {
			return err
		}
	}
	for name := range groups {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, err := i.ensureGroup(ctx, name); err != nil {
			return err
		}
	}

	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM group_members"); err != nil {
		return err
	}
	for groupName, members := range groups {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" {
			continue
		}
		groupID, err := i.groupIDByNameTx(ctx, tx, groupName)
		if err != nil {
			return err
		}
		for _, member := range members {
			user := strings.TrimSpace(member.User)
			if user == "" {
				continue
			}
			access := strings.ToLower(strings.TrimSpace(member.Access))
			if access != "ro" && access != "rw" {
				access = "ro"
			}
			userID, err := i.userIDByNameTx(ctx, tx, user)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO group_members(group_id, user_id, access)
				VALUES(?, ?, ?)
			`, groupID, userID, access); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func (i *Index) CanWriteOwner(ctx context.Context, ownerName, userName string) (bool, error) {
	ownerName = strings.TrimSpace(ownerName)
	userName = strings.TrimSpace(userName)
	if ownerName == "" || userName == "" {
		return false, nil
	}
	if ownerName == userName {
		return true, nil
	}
	groupID, err := i.groupIDByName(ctx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	userID, err := i.userIDByName(ctx, userName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var access string
	err = i.db.QueryRowContext(ctx, `
		SELECT access
		FROM group_members
		WHERE group_id=? AND user_id=?
	`, groupID, userID).Scan(&access)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(access, "rw"), nil
}

func (i *Index) ensureUser(ctx context.Context, name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("empty user name")
	}
	if _, err := i.db.ExecContext(ctx, "INSERT OR IGNORE INTO users(name) VALUES(?)", name); err != nil {
		return 0, err
	}
	return i.userIDByName(ctx, name)
}

func (i *Index) EnsureUser(ctx context.Context, name string) (int, error) {
	return i.ensureUser(ctx, name)
}

func (i *Index) ensureGroup(ctx context.Context, name string) (int, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("empty group name")
	}
	if _, err := i.db.ExecContext(ctx, "INSERT OR IGNORE INTO groups(name) VALUES(?)", name); err != nil {
		return 0, err
	}
	return i.groupIDByName(ctx, name)
}

func (i *Index) userIDByName(ctx context.Context, name string) (int, error) {
	return i.userIDByNameTx(ctx, i.db, name)
}

func (i *Index) groupIDByName(ctx context.Context, name string) (int, error) {
	return i.groupIDByNameTx(ctx, i.db, name)
}

type queryerTx interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (i *Index) userIDByNameTx(ctx context.Context, q queryerTx, name string) (int, error) {
	var id int
	err := q.QueryRowContext(ctx, "SELECT id FROM users WHERE name=?", name).Scan(&id)
	return id, err
}

func (i *Index) groupIDByNameTx(ctx context.Context, q queryerTx, name string) (int, error) {
	var id int
	err := q.QueryRowContext(ctx, "SELECT id FROM groups WHERE name=?", name).Scan(&id)
	return id, err
}

func (i *Index) ResolveOwnerIDs(ctx context.Context, ownerName string) (int, sql.NullInt64, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, sql.NullInt64{}, fmt.Errorf("empty owner name")
	}
	groupID, err := i.groupIDByName(ctx, ownerName)
	if err == nil {
		userID, err := i.actorUserID(ctx)
		if err != nil {
			return 0, sql.NullInt64{}, err
		}
		return userID, sql.NullInt64{Int64: int64(groupID), Valid: true}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, sql.NullInt64{}, err
	}
	userID, err := i.ensureUser(ctx, ownerName)
	if err != nil {
		return 0, sql.NullInt64{}, err
	}
	return userID, sql.NullInt64{}, nil
}

func (i *Index) LookupOwnerIDs(ctx context.Context, ownerName string) (int, sql.NullInt64, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, sql.NullInt64{}, fmt.Errorf("empty owner name")
	}
	groupID, groupErr := i.groupIDByName(ctx, ownerName)
	userID, userErr := i.userIDByName(ctx, ownerName)
	if groupErr == nil && userErr == nil {
		return 0, sql.NullInt64{}, fmt.Errorf("owner name %q is both user and group", ownerName)
	}
	if groupErr == nil {
		return 0, sql.NullInt64{Int64: int64(groupID), Valid: true}, nil
	}
	if userErr == nil {
		return userID, sql.NullInt64{}, nil
	}
	if errors.Is(groupErr, sql.ErrNoRows) && errors.Is(userErr, sql.ErrNoRows) {
		return 0, sql.NullInt64{}, sql.ErrNoRows
	}
	if groupErr != nil && !errors.Is(groupErr, sql.ErrNoRows) {
		return 0, sql.NullInt64{}, groupErr
	}
	if userErr != nil && !errors.Is(userErr, sql.ErrNoRows) {
		return 0, sql.NullInt64{}, userErr
	}
	return 0, sql.NullInt64{}, sql.ErrNoRows
}

func (i *Index) AccessFilterForUser(ctx context.Context, userName string) (int, []int, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return 0, nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return 0, nil, err
	}
	rows, err := i.db.QueryContext(ctx, `
		SELECT group_members.group_id
		FROM group_members
		WHERE group_members.user_id = ?
	`, userID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var groupIDs []int
	for rows.Next() {
		var groupID int
		if err := rows.Scan(&groupID); err != nil {
			return 0, nil, err
		}
		groupIDs = append(groupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return userID, groupIDs, nil
}

func (i *Index) WritableGroupsForUser(ctx context.Context, userName string) ([]string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.db.QueryContext(ctx, `
		SELECT groups.name
		FROM group_members
		JOIN groups ON groups.id = group_members.group_id
		WHERE group_members.user_id = ? AND lower(group_members.access) = 'rw'
		ORDER BY groups.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		groups = append(groups, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}

func (i *Index) actorUserID(ctx context.Context) (int, error) {
	if filter, ok := accessFilterFromContext(ctx); ok && filter.userID > 0 {
		return filter.userID, nil
	}
	return i.ensureUser(ctx, "system")
}
