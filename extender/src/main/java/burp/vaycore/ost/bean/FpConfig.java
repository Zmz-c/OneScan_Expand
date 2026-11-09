package burp.vaycore.ost.bean;

import burp.vaycore.common.utils.GsonUtils;
import burp.vaycore.ost.manager.FpManager;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * 指纹配置
 * <p>
 * Created by vaycore on 2025-05-19.
 */
public class FpConfig {

    // Serialize writes; idle workers expire so unloading an extension does not retain a permanent thread.
    private static final ExecutorService WRITER = new ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(), runnable -> {
                Thread thread = new Thread(runnable, "ost-fingerprint-save");
                thread.setDaemon(true);
                return thread;
            });

    /**
     * 指纹字段
     */
    private List<FpColumn> columns;

    /**
     * 指纹数据
     */
    private List<FpData> list;

    /**
     * 获取指纹字段列表
     *
     * @return 失败返回空列表
     */
    public List<FpColumn> getColumns() {
        if (columns == null) {
            columns = new ArrayList<>();
        }
        return columns;
    }

    /**
     * 获取指纹字段数量
     *
     * @return 指纹字段数量
     */
    public int getColumnsSize() {
        if (columns == null || columns.isEmpty()) {
            return 0;
        }
        return columns.size();
    }

    /**
     * 添加指纹字段
     *
     * @param column 指纹字段数据实例
     */
    public void addColumnsItem(FpColumn column) {
        if (column != null) {
            columns.add(column);
            writeToFile();
        }
    }

    /**
     * 移除指纹字段数据
     *
     * @param index 数据下标
     * @return 移除的字段数据实例
     */
    public FpColumn removeColumnsItem(int index) {
        if (index >= 0 && index < getColumnsSize()) {
            FpColumn column = columns.remove(index);
            writeToFile();
            return column;
        }
        return null;
    }

    /**
     * 更新指纹字段数据
     *
     * @param index  下标
     * @param column 指纹字段实例
     */
    public void setColumnsItem(int index, FpColumn column) {
        if (column == null || getColumnsSize() == 0) {
            return;
        }
        if (index < 0 || index >= getColumnsSize()) {
            return;
        }
        columns.set(index, column);
        writeToFile();
    }

    /**
     * 设置指纹字段列表
     *
     * @param columns 指纹字段列表
     */
    public void setColumns(ArrayList<FpColumn> columns) {
        if (columns == null) {
            this.columns = new ArrayList<>();
        } else {
            this.columns = new ArrayList<>(columns);
        }
        writeToFile();
    }

    /**
     * 获取指纹数据列表
     *
     * @return 失败返回空列表
     */
    public List<FpData> getList() {
        if (list == null) {
            list = new ArrayList<>();
        }
        return list;
    }

    /**
     * 获取指纹数据数量
     *
     * @return 指纹数量
     */
    public int getListSize() {
        if (list == null || list.isEmpty()) {
            return 0;
        }
        return list.size();
    }


    /**
     * 添加指纹数据
     *
     * @param data 指纹数据实例
     */
    public void addListItem(FpData data) {
        if (data != null && !data.getRules().isEmpty()) {
            list.add(data);
            writeToFile();
        }
    }

    /**
     * 移除指纹数据
     *
     * @param index 数据下标
     */
    public void removeListItem(int index) {
        if (index >= 0 && index < getListSize()) {
            list.remove(index);
            writeToFile();
        }
    }

    /**
     * 更新指纹数据
     *
     * @param index 下标
     * @param data  指纹数据实例
     */
    public void setListItem(int index, FpData data) {
        if (getListSize() == 0) {
            return;
        }
        if (index < 0 || index >= getListSize()) {
            return;
        }
        if (data != null && !data.getRules().isEmpty()) {
            list.set(index, data);
            writeToFile();
        }
    }

    /**
     * 设置指纹数据列表
     *
     * @param list 数据列表
     */
    public void setList(List<FpData> list) {
        if (list == null) {
            this.list = new ArrayList<>();
        } else {
            this.list = new ArrayList<>(list);
        }
        writeToFile();
    }

    /**
     * 写入配置到文件中
     */
    private void writeToFile() {
        // 后台保存
        String path = FpManager.getPath();
        String snapshot = GsonUtils.toJson(this);
        WRITER.execute(() -> saveToFile(path, snapshot));
    }

    public void saveNow() {
        String path = FpManager.getPath();
        String snapshot = GsonUtils.toJson(this);
        try {
            WRITER.submit(() -> saveToFile(path, snapshot)).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Fingerprint save interrupted", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException("Fingerprint save failed", e.getCause());
        }
    }

    private static void saveToFile(String path, String snapshot) {
        synchronized (FpConfig.class) {
            Path target = Path.of(path).toAbsolutePath();
            Path temp = null;
            try {
                temp = Files.createTempFile(target.getParent(), "fingerprints-", ".tmp");
                Files.writeString(temp, snapshot);
                try {
                    Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } finally {
                if (temp != null) try { Files.deleteIfExists(temp); } catch (IOException ignored) { }
            }
        }
    }
}
