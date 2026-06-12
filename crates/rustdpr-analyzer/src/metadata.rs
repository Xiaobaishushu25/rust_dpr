use anyhow::{Result, anyhow};
use cargo_metadata::MetadataCommand;
use rustdpr_core::model::{CrateMeta, TargetMeta};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 收集 Crate 的元数据信息
///
/// # 参数
/// * `crate_dir` - Crate 根目录路径
///
/// # 返回值
/// 返回包含 Crate 名称、版本、目标等信息的 CrateMeta 结构
pub fn collect_metadata(crate_dir: &Path) -> Result<CrateMeta> {
    // 执行 cargo metadata 命令获取元数据
    let metadata = MetadataCommand::new().current_dir(crate_dir).exec()?;

    // 获取根包（root package）
    let root_pkg = metadata
        .root_package()
        .ok_or_else(|| anyhow!("no root package found for {:?}", crate_dir))?;

    // 转换目标信息
    let targets = root_pkg
        .targets
        .iter()
        .map(|t| TargetMeta {
            name: t.name.clone(),
            kind: t.kind.iter().map(|k| k.to_string()).collect(),
            src_path: t.src_path.clone().into_std_path_buf(),
        })
        .collect();

    // 收集特性配置
    let mut features = BTreeMap::new();
    for (k, v) in &root_pkg.features {
        features.insert(k.clone(), v.clone());
    }

    Ok(CrateMeta {
        name: root_pkg.name.clone(),
        version: root_pkg.version.to_string(),
        manifest_path: root_pkg.manifest_path.clone().into_std_path_buf(),
        workspace_root: metadata.workspace_root.clone().into_std_path_buf(),
        targets,
        features,
    })
}

#[derive(Debug, Clone)]
pub struct DependencySource {
    pub name: String,
    pub version: String,
    pub manifest_path: PathBuf,
    pub root_dir: PathBuf,
    pub source_origin: String,
}

/// Locate dependency source roots through `cargo metadata`.
///
/// If `dep_crates` is empty, all resolved dependencies are returned. For the
/// default benchmark path this function is never called; it is opt-in through
/// `rustdpr-cli analyze-sites --include-deps`.
pub fn collect_dependency_sources(
    crate_dir: &Path,
    dep_crates: &[String],
) -> Result<Vec<DependencySource>> {
    let metadata = MetadataCommand::new().current_dir(crate_dir).exec()?;
    let metadata1 = metadata.clone();
    let root_pkg = metadata1
        .root_package()
        .ok_or_else(|| anyhow!("no root package found for {:?}", crate_dir))?;

    let requested: std::collections::BTreeSet<String> = dep_crates
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut result = Vec::new();
    for pkg in metadata.packages {
        if pkg.id == root_pkg.id {
            continue;
        }
        if !requested.is_empty() && !requested.contains(pkg.name.as_str()) {
            continue;
        }

        let manifest_path = pkg.manifest_path.clone().into_std_path_buf();
        let root_dir = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("dependency manifest has no parent: {:?}", manifest_path))?
            .to_path_buf();

        result.push(DependencySource {
            name: pkg.name.to_string(),
            version: pkg.version.to_string(),
            manifest_path,
            root_dir,
            source_origin: "dependency".to_string(),
        });
    }

    result.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    Ok(result)
}
