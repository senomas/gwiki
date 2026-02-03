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

type OwnerSyncStats struct {
	UsersInFile    int
	UsersAdded     int
	UsersUpdated   int
}

type AccessSyncStats struct {
	OwnersInFile    int
	GrantsAdded     int
	GrantsUpdated   int
	GrantsRemoved   int
}

func (i *Index) SyncOwners(ctx context.Context, users []string, groups map[string][]GroupMember) error {
	_, err := i.SyncOwnersWithStats(ctx, users, groups)
	return err
}

func (i *Index) SyncOwnersWithStats(ctx context.Context, users []string, groups map[string][]GroupMember) (OwnerSyncStats, error) {
	userSet := map[string]struct{}{}
	for _, name := range users {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		userSet[name] = struct{}{}
	}
	userSet["system"] = struct{}{}

	stats := OwnerSyncStats{
		UsersInFile: len(users),
	}

	for name := range userSet {
		created, err := i.ensureUser(ctx, name)
		if err != nil {
			return stats, err
		}
		if created {
			stats.UsersAdded++
		}
	}

	return stats, nil
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
	userID, err := i.userIDByName(ctx, userName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ownerID, err := i.userIDByName(ctx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var access string
	err = i.queryRowContext(ctx, `
		SELECT access
		FROM user_access
		WHERE owner_user_id=? AND grantee_user_id=?
	`, ownerID, userID).Scan(&access)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(access, "rw"), nil
}

func (i *Index) ensureUser(ctx context.Context, name string) (bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, fmt.Errorf("empty user name")
	}
	if _, err := i.execContext(ctx, "INSERT OR IGNORE INTO users(name) VALUES(?)", name); err != nil {
		return false, err
	}
	userID, err := i.userIDByName(ctx, name)
	if err != nil {
		return false, err
	}
	var changes int64
	if err := i.queryRowContext(ctx, "SELECT changes()").Scan(&changes); err != nil {
		return false, err
	}
	return changes > 0 && userID > 0, nil
}

func (i *Index) EnsureUser(ctx context.Context, name string) (int, error) {
	_, err := i.ensureUser(ctx, name)
	if err != nil {
		return 0, err
	}
	return i.userIDByName(ctx, name)
}

func (i *Index) ensureGroup(ctx context.Context, name string) (bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, fmt.Errorf("empty group name")
	}
	if _, err := i.execContext(ctx, "INSERT OR IGNORE INTO groups(name) VALUES(?)", name); err != nil {
		return false, err
	}
	groupID, err := i.groupIDByName(ctx, name)
	if err != nil {
		return false, err
	}
	var changes int64
	if err := i.queryRowContext(ctx, "SELECT changes()").Scan(&changes); err != nil {
		return false, err
	}
	return changes > 0 && groupID > 0, nil
}

func (i *Index) SyncUserAccessWithStats(ctx context.Context, access map[string][]GroupMember) (AccessSyncStats, error) {
	stats := AccessSyncStats{OwnersInFile: len(access)}
	existing := map[string]string{}
	rows, err := i.queryContext(ctx, `
		SELECT owners.name, grantees.name, user_access.access
		FROM user_access
		JOIN users owners ON owners.id = user_access.owner_user_id
		JOIN users grantees ON grantees.id = user_access.grantee_user_id
	`)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var ownerName, granteeName, accessLevel string
		if err := rows.Scan(&ownerName, &granteeName, &accessLevel); err != nil {
			rows.Close()
			return stats, err
		}
		key := strings.ToLower(strings.TrimSpace(ownerName)) + "|" + strings.ToLower(strings.TrimSpace(granteeName))
		if key == "|" {
			continue
		}
		existing[key] = strings.ToLower(strings.TrimSpace(accessLevel))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stats, err
	}
	rows.Close()

	desired := map[string]string{}
	for ownerName, members := range access {
		ownerName = strings.TrimSpace(ownerName)
		if ownerName == "" {
			continue
		}
		for _, member := range members {
			user := strings.TrimSpace(member.User)
			if user == "" {
				continue
			}
			level := strings.ToLower(strings.TrimSpace(member.Access))
			if level != "ro" && level != "rw" {
				level = "ro"
			}
			key := strings.ToLower(ownerName) + "|" + strings.ToLower(user)
			desired[key] = level
		}
	}

	for key, level := range desired {
		prev, ok := existing[key]
		if !ok {
			stats.GrantsAdded++
			continue
		}
		if prev != level {
			stats.GrantsUpdated++
		}
	}
	for key := range existing {
		if _, ok := desired[key]; !ok {
			stats.GrantsRemoved++
		}
	}

	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return stats, err
	}
	defer tx.Rollback()

	if _, err := i.execContextTx(ctx, tx, "DELETE FROM user_access"); err != nil {
		return stats, err
	}
	for ownerName, members := range access {
		ownerName = strings.TrimSpace(ownerName)
		if ownerName == "" {
			continue
		}
		if _, err := i.ensureUser(ctx, ownerName); err != nil {
			return stats, err
		}
		ownerID, err := i.userIDByNameTx(ctx, tx, ownerName)
		if err != nil {
			return stats, err
		}
		for _, member := range members {
			user := strings.TrimSpace(member.User)
			if user == "" {
				continue
			}
			accessLevel := strings.ToLower(strings.TrimSpace(member.Access))
			if accessLevel != "ro" && accessLevel != "rw" {
				accessLevel = "ro"
			}
			if _, err := i.ensureUser(ctx, user); err != nil {
				return stats, err
			}
			userID, err := i.userIDByNameTx(ctx, tx, user)
			if err != nil {
				return stats, err
			}
			if _, err := i.execContextTx(ctx, tx, `
				INSERT INTO user_access(owner_user_id, grantee_user_id, access)
				VALUES(?, ?, ?)
			`, ownerID, userID, accessLevel); err != nil {
				return stats, err
			}
		}
	}

	return stats, tx.Commit()
}

func (i *Index) WritableOwnersForUser(ctx context.Context, userName string) ([]string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.queryContext(ctx, `
		SELECT owners.name
		FROM user_access
		JOIN users owners ON owners.id = user_access.owner_user_id
		WHERE user_access.grantee_user_id = ? AND lower(user_access.access) = 'rw'
		ORDER BY owners.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		owners = append(owners, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return owners, nil
}

func (i *Index) AccessibleOwnersForUser(ctx context.Context, userName string) ([]string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.queryContext(ctx, `
		SELECT owners.name
		FROM user_access
		JOIN users owners ON owners.id = user_access.owner_user_id
		WHERE user_access.grantee_user_id = ?
		ORDER BY owners.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		owners = append(owners, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return owners, nil
}

func (i *Index) userIDByName(ctx context.Context, name string) (int, error) {
	return i.userIDByNameTx(ctx, nil, name)
}

func (i *Index) groupIDByName(ctx context.Context, name string) (int, error) {
	return i.groupIDByNameTx(ctx, nil, name)
}

func (i *Index) userIDByNameTx(ctx context.Context, tx *sql.Tx, name string) (int, error) {
	var id int
	if tx != nil {
		err := i.queryRowContextTx(ctx, tx, "SELECT id FROM users WHERE name=?", name).Scan(&id)
		return id, err
	}
	err := i.queryRowContext(ctx, "SELECT id FROM users WHERE name=?", name).Scan(&id)
	return id, err
}

func (i *Index) groupIDByNameTx(ctx context.Context, tx *sql.Tx, name string) (int, error) {
	var id int
	if tx != nil {
		err := i.queryRowContextTx(ctx, tx, "SELECT id FROM groups WHERE name=?", name).Scan(&id)
		return id, err
	}
	err := i.queryRowContext(ctx, "SELECT id FROM groups WHERE name=?", name).Scan(&id)
	return id, err
}

func (i *Index) ResolveOwnerIDs(ctx context.Context, ownerName string) (int, sql.NullInt64, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, sql.NullInt64{}, fmt.Errorf("empty owner name")
	}
	if _, err := i.ensureUser(ctx, ownerName); err != nil {
		return 0, sql.NullInt64{}, err
	}
	userID, err := i.userIDByName(ctx, ownerName)
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
	userID, err := i.userIDByName(ctx, ownerName)
	if err == nil {
		return userID, sql.NullInt64{}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, sql.NullInt64{}, err
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
	rows, err := i.queryContext(ctx, `
		SELECT owner_user_id
		FROM user_access
		WHERE grantee_user_id = ?
	`, userID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	var ownerIDs []int
	for rows.Next() {
		var ownerID int
		if err := rows.Scan(&ownerID); err != nil {
			return 0, nil, err
		}
		ownerIDs = append(ownerIDs, ownerID)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return userID, ownerIDs, nil
}


func (i *Index) actorUserID(ctx context.Context) (int, error) {
	if filter, ok := accessFilterFromContext(ctx); ok && filter.userID > 0 {
		return filter.userID, nil
	}
	_, err := i.ensureUser(ctx, "system")
	if err != nil {
		return 0, err
	}
	return i.userIDByName(ctx, "system")
}

func (i *Index) ListUsers(ctx context.Context) ([]string, error) {
	rows, err := i.queryContext(ctx, "SELECT name FROM users ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		users = append(users, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
