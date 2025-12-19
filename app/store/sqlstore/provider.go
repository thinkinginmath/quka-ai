package sqlstore

import (
	"context"
	"embed"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	_ "github.com/lib/pq"

	"github.com/quka-ai/quka-ai/app/store"
	"github.com/quka-ai/quka-ai/pkg/register"
	"github.com/quka-ai/quka-ai/pkg/sqlstore"
	"github.com/quka-ai/quka-ai/pkg/types"
)

func init() {
	sq.StatementBuilder = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}

var provider = &Provider{
	stores: &Stores{},
}

func GetProvider() *Provider {
	return provider
}

type Provider struct {
	*sqlstore.SqlProvider
	stores *Stores
	coreRef *CoreRef
}

// CoreRef 用于延迟获取 core 实例，避免循环依赖
type CoreRef struct {
	getCacheFunc func() types.Cache
}

type Stores struct {
	store.KnowledgeStore
	store.KnowledgeChunkStore
	store.VectorStore
	store.AccessTokenStore
	store.UserSpaceStore
	store.UserGlobalRoleStore
	store.SpaceStore
	store.ResourceStore
	store.UserStore
	store.ChatSessionStore
	store.ChatSessionPinStore
	store.ChatMessageStore
	store.ChatSummaryStore
	store.ChatMessageExtStore
	store.FileManagementStore
	store.AITokenUsageStore
	store.ShareTokenStore
	store.SpaceApplicationStore
	store.JournalStore
	store.ButlerTableStore
	store.ModelProviderStore
	store.ModelConfigStore
	store.CustomConfigStore
	store.SpaceInvitationStore
	store.ContentTaskStore
	store.KnowledgeMetaStore
	store.KnowledgeRelMetaStore
}

func (s *Provider) batchExecStoreFuncs(fname string) {
	val := reflect.ValueOf(s.stores)
	num := val.NumField()
	for i := 0; i < num; i++ {
		val.Field(i).MethodByName(fname).Call([]reflect.Value{})
	}
}

type RegisterKey struct{}

func MustSetup(m sqlstore.ConnectConfig, s ...sqlstore.ConnectConfig) func() *Provider {

	provider.SqlProvider = sqlstore.MustSetupProvider(m, s...)

	for _, f := range register.ResolveFuncHandlers[*Provider](RegisterKey{}) {
		f(provider)
	}

	return func() *Provider {
		return provider
	}
}

// MigrationRecord represents a migration record in the database
type MigrationRecord struct {
	Filename   string `db:"filename"`
	ExecutedAt int64  `db:"executed_at"`
}

// Install 初始化所有数据表
func (p *Provider) Install() error {
	// 首先启用必要的数据库扩展
	if err := p.enableExtensions(); err != nil {
		return err
	}

	// 确保迁移记录表存在
	if err := p.ensureMigrationTable(); err != nil {
		return err
	}

	// 1. 执行 schema 文件 (表创建)
	files, err := CreateTableFiles.ReadDir(".")
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sql") {
			if err := p.runMigrationFile(file.Name(), CreateTableFiles); err != nil {
				return err
			}
		}
	}

	// 2. 执行 migrations 文件 (增量变更)
	migrationFiles, err := MigrationFiles.ReadDir("migrations")
	if err != nil {
		// migrations 目录可能不存在，忽略错误
		return nil
	}

	for _, file := range migrationFiles {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sql") {
			// 使用带前缀的文件名来区分 schema 和 migration
			migrationName := "migrations/" + file.Name()
			if err := p.runMigrationFileWithPath(migrationName, "migrations/"+file.Name(), MigrationFiles); err != nil {
				return err
			}
		}
	}

	return nil
}

// runMigrationFile 执行单个迁移文件 (从 embed.FS 读取)
func (p *Provider) runMigrationFile(filename string, fs embed.FS) error {
	// 检查文件是否已经执行过
	if executed, err := p.isFileExecuted(filename); err != nil {
		return err
	} else if executed {
		return nil // 跳过已执行的文件
	}

	sql, err := fs.ReadFile(filename)
	if err != nil {
		return err
	}

	// 执行SQL文件内容
	if err = p.executeSQLFile(string(sql), filename); err != nil {
		return err
	}

	// 记录文件已执行
	return p.markFileExecuted(filename)
}

// runMigrationFileWithPath 执行迁移文件，支持不同的记录名和文件路径
func (p *Provider) runMigrationFileWithPath(recordName, filePath string, fs embed.FS) error {
	// 检查文件是否已经执行过
	if executed, err := p.isFileExecuted(recordName); err != nil {
		return err
	} else if executed {
		return nil // 跳过已执行的文件
	}

	sql, err := fs.ReadFile(filePath)
	if err != nil {
		return err
	}

	// 执行SQL文件内容
	if err = p.executeSQLFile(string(sql), recordName); err != nil {
		return err
	}

	// 记录文件已执行
	return p.markFileExecuted(recordName)
}

// enableExtensions 启用必要的数据库扩展
// 如需添加更多扩展，只需在 extensions 切片中添加相应的 SQL 语句
func (p *Provider) enableExtensions() error {
	extensions := []string{
		"CREATE EXTENSION IF NOT EXISTS vector;", // pgvector 扩展，用于向量操作
		// 可以在这里添加更多扩展，例如：
		// "CREATE EXTENSION IF NOT EXISTS uuid-ossp;", // UUID 生成功能
		// "CREATE EXTENSION IF NOT EXISTS pg_trgm;",   // 模糊字符串匹配
	}

	for _, ext := range extensions {
		if _, err := p.SqlProvider.GetMaster().Exec(ext); err != nil {
			return fmt.Errorf("failed to enable extension: %w\nSQL: %s", err, ext)
		}
	}
	return nil
}

// ensureMigrationTable 确保迁移记录表存在
func (p *Provider) ensureMigrationTable() error {
	createTableSQL := `
CREATE TABLE IF NOT EXISTS ` + types.TABLE_PREFIX + `schema_migrations (
    filename VARCHAR(255) PRIMARY KEY,
    executed_at BIGINT NOT NULL
);`
	_, err := p.SqlProvider.GetMaster().Exec(createTableSQL)
	return err
}

// isFileExecuted 检查文件是否已经执行过
func (p *Provider) isFileExecuted(filename string) (bool, error) {
	var count int
	err := p.SqlProvider.GetReplica().Get(&count,
		"SELECT COUNT(*) FROM "+types.TABLE_PREFIX+"schema_migrations WHERE filename = $1", filename)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// markFileExecuted 标记文件为已执行
func (p *Provider) markFileExecuted(filename string) error {
	_, err := p.SqlProvider.GetMaster().Exec(
		"INSERT INTO "+types.TABLE_PREFIX+"schema_migrations (filename, executed_at) VALUES ($1, $2) ON CONFLICT (filename) DO NOTHING",
		filename, time.Now().Unix())
	return err
}

// executeSQLFile 执行SQL文件内容，分割语句并逐个执行
func (p *Provider) executeSQLFile(content, filename string) error {
	fmt.Printf("📄 Executing migration: %s\n", filename)
	// 执行语句
	if _, err := p.SqlProvider.GetMaster().Exec(content); err != nil {
		return fmt.Errorf("failed to execute %s: %w", filename, err)
	}
	fmt.Printf("✅ Completed: %s\n", filename)
	return nil
}

// GetAllMigrationFiles 获取所有迁移文件列表 (schema + migrations)
func (p *Provider) GetAllMigrationFiles() ([]string, error) {
	var allFiles []string

	// 1. 获取 schema 文件
	schemaFiles, err := CreateTableFiles.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read schema files: %w", err)
	}
	for _, f := range schemaFiles {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".sql") {
			allFiles = append(allFiles, f.Name())
		}
	}

	// 2. 获取 migration 文件
	migrationFiles, err := MigrationFiles.ReadDir("migrations")
	if err == nil {
		for _, f := range migrationFiles {
			if !f.IsDir() && strings.HasSuffix(f.Name(), ".sql") {
				allFiles = append(allFiles, "migrations/"+f.Name())
			}
		}
	}

	sort.Strings(allFiles)
	return allFiles, nil
}

// GetExecutedMigrations 获取已执行的迁移记录
func (p *Provider) GetExecutedMigrations() ([]MigrationRecord, error) {
	// 先确保表存在
	if err := p.ensureMigrationTable(); err != nil {
		return nil, err
	}

	var records []MigrationRecord
	query := "SELECT filename, executed_at FROM " + types.TABLE_PREFIX + "schema_migrations ORDER BY filename"
	if err := p.SqlProvider.GetReplica().Select(&records, query); err != nil {
		return nil, fmt.Errorf("failed to get executed migrations: %w", err)
	}
	return records, nil
}

// GetPendingMigrations 获取待执行的迁移文件列表
func (p *Provider) GetPendingMigrations() ([]string, error) {
	allFiles, err := p.GetAllMigrationFiles()
	if err != nil {
		return nil, err
	}

	executed, err := p.GetExecutedMigrations()
	if err != nil {
		return nil, err
	}

	executedMap := make(map[string]bool)
	for _, m := range executed {
		executedMap[m.Filename] = true
	}

	var pending []string
	for _, f := range allFiles {
		if !executedMap[f] {
			pending = append(pending, f)
		}
	}

	return pending, nil
}

func (p *Provider) store() *Stores {
	return p.stores
}

func (p *Provider) KnowledgeStore() store.KnowledgeStore {
	return p.stores.KnowledgeStore
}

func (p *Provider) VectorStore() store.VectorStore {
	return p.stores.VectorStore
}

func (p *Provider) AccessTokenStore() store.AccessTokenStore {
	return p.stores.AccessTokenStore
}

func (p *Provider) UserSpaceStore() store.UserSpaceStore {
	return p.stores.UserSpaceStore
}

func (p *Provider) UserGlobalRoleStore() store.UserGlobalRoleStore {
	return p.stores.UserGlobalRoleStore
}

func (p *Provider) SpaceStore() store.SpaceStore {
	return p.stores.SpaceStore
}

func (p *Provider) ResourceStore() store.ResourceStore {
	return p.stores.ResourceStore
}

func (p *Provider) UserStore() store.UserStore {
	return p.stores.UserStore
}

func (p *Provider) KnowledgeChunkStore() store.KnowledgeChunkStore {
	return p.stores.KnowledgeChunkStore
}

func (p *Provider) ChatSessionStore() store.ChatSessionStore {
	return p.stores.ChatSessionStore
}

func (p *Provider) ChatMessageStore() store.ChatMessageStore {
	return p.stores.ChatMessageStore
}

func (p *Provider) ChatSummaryStore() store.ChatSummaryStore {
	return p.stores.ChatSummaryStore
}

func (p *Provider) ChatMessageExtStore() store.ChatMessageExtStore {
	return p.stores.ChatMessageExtStore
}

func (p *Provider) FileManagementStore() store.FileManagementStore {
	return p.stores.FileManagementStore
}

func (p *Provider) AITokenUsageStore() store.AITokenUsageStore {
	return p.stores.AITokenUsageStore
}

func (p *Provider) ShareTokenStore() store.ShareTokenStore {
	return p.stores.ShareTokenStore
}

func (p *Provider) JournalStore() store.JournalStore {
	return p.stores.JournalStore
}

func (p *Provider) ChatSessionPinStore() store.ChatSessionPinStore {
	return p.stores.ChatSessionPinStore
}

func (p *Provider) BulterTableStore() store.ButlerTableStore {
	return p.stores.ButlerTableStore
}

func (p *Provider) SpaceApplicationStore() store.SpaceApplicationStore {
	return p.stores.SpaceApplicationStore
}

func (p *Provider) ModelProviderStore() store.ModelProviderStore {
	return p.stores.ModelProviderStore
}

func (p *Provider) ModelConfigStore() store.ModelConfigStore {
	return p.stores.ModelConfigStore
}

func (p *Provider) CustomConfigStore() store.CustomConfigStore {
	return p.stores.CustomConfigStore
}

func (p *Provider) SpaceInvitationStore() store.SpaceInvitationStore {
	return p.stores.SpaceInvitationStore
}

func (p *Provider) ContentTaskStore() store.ContentTaskStore {
	return p.stores.ContentTaskStore
}

func (p *Provider) KnowledgeMetaStore() store.KnowledgeMetaStore {
	return p.stores.KnowledgeMetaStore
}

func (p *Provider) KnowledgeRelMetaStore() store.KnowledgeRelMetaStore {
	return p.stores.KnowledgeRelMetaStore
}

// Cache 实现 Author 接口的 Cache 方法
func (p *Provider) Cache() types.Cache {
	if p.coreRef != nil && p.coreRef.getCacheFunc != nil {
		return p.coreRef.getCacheFunc()
	}
	// 返回一个空的 cache 实现作为fallback
	return &EmptyCache{}
}

// SetCacheFunc 设置获取 cache 的函数
func (p *Provider) SetCacheFunc(getCacheFunc func() types.Cache) {
	if p.coreRef == nil {
		p.coreRef = &CoreRef{}
	}
	p.coreRef.getCacheFunc = getCacheFunc
}

// EmptyCache 空的 cache 实现，用作 fallback
type EmptyCache struct{}

func (c *EmptyCache) Get(ctx context.Context, key string) (string, error) {
	return "", nil
}

func (c *EmptyCache) SetEx(ctx context.Context, key, value string, expiresAt time.Duration) error {
	return nil
}

func (c *EmptyCache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return nil
}
