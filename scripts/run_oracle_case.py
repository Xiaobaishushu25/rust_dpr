"""
Oracle测试用例执行脚本

该脚本用于运行完整的Oracle测试流程，包括：
1. 分析潜在错误站点
2. 运行ASAN内存检测
3. 解析Oracle结果
4. 分类错误类型
5. 生成报告
"""
import subprocess
import sys
from pathlib import Path


def run(cmd):
    """
    执行系统命令并打印命令内容
    
    Args:
        cmd: 要执行的命令列表
        
    Raises:
        subprocess.CalledProcessError: 当命令执行失败时抛出异常
    """
    print(">", " ".join(map(str, cmd)))
    subprocess.run(cmd, check=True)


def main(case_name: str):
    """
    主函数：执行完整的Oracle测试流程
    
    Args:
        case_name: 测试用例名称，对应benchmarks/oracle目录下的子目录名
    """
    # 获取项目根目录（脚本所在目录的父目录）
    root = Path(__file__).resolve().parent.parent
    
    # 构建各个目录路径
    case_dir = root / "benchmarks" / "oracle" / case_name  # 测试用例目录
    data_dir = root / "data" / case_name                   # 数据存储目录
    oracle_dir = data_dir / "oracle"                       # Oracle结果目录
    report_path = root / "reports" / f"{case_name}.md"     # 报告输出路径

    # 创建必要的目录（如果不存在则创建）
    data_dir.mkdir(parents=True, exist_ok=True)
    oracle_dir.mkdir(parents=True, exist_ok=True)

    # 步骤1: 分析潜在错误站点
    # 使用rustdpr-cli工具分析测试用例中的潜在错误位置
    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "analyze-sites",
        "--crate-dir", str(case_dir),
        "--out", str(data_dir / "site_map.json"),
    ])

    # 步骤2: 运行ASAN内存检测
    # 使用AddressSanitizer检测内存错误（如use-after-free、double-free等）
    run([
        sys.executable, str(root / "scripts" / "run_asan.py"),
        str(case_dir), str(oracle_dir),
    ])

    # 步骤3: 解析Oracle结果
    # 将ASAN日志解析为标准化的JSON格式
    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "oracle-parse",
        "--asan-log", str(oracle_dir / "asan.log"),
        "--out", str(oracle_dir / "oracle_result.json"),
    ])

    # 步骤4: 错误分类
    # 根据trace信息、站点映射和Oracle结果对错误进行分类
    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "classify",
        "--trace", str(case_dir / "trace.jsonl"),
        "--site-map", str(data_dir / "site_map.json"),
        "--oracle", str(oracle_dir / "oracle_result.json"),
        "--out", str(data_dir / "classification.json"),
    ])

    # 步骤5: 生成报告
    # 基于所有分析结果生成Markdown格式的详细报告
    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "report",
        "--trace", str(case_dir / "trace.jsonl"),
        "--site-map", str(data_dir / "site_map.json"),
        "--result", str(data_dir / "classification.json"),
        "--oracle", str(oracle_dir / "oracle_result.json"),
        "--out", str(report_path),
    ])

    print(f"done: {case_name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scripts/run_oracle_case.py <case_name>")
        sys.exit(1)

    main(sys.argv[1])