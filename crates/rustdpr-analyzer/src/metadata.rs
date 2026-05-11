use anyhow::{anyhow, Result};
use cargo_metadata::MetadataCommand;
use rustdpr_core::model::{CrateMeta, TargetMeta};
use std::collections::BTreeMap;
use std::path::Path;

/// 收集 Crate 的元数据信息
/// 
/// # 参数
/// * `crate_dir` - Crate 根目录路径
/// 
/// # 返回值
/// 返回包含 Crate 名称、版本、目标等信息的 CrateMeta 结构
pub fn collect_metadata(crate_dir: &Path) -> Result<CrateMeta> {
    // 执行 cargo metadata 命令获取元数据
    let metadata = MetadataCommand::new()
        .current_dir(crate_dir)
        .exec()?;

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