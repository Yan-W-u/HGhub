import { useCallback, useEffect, useRef, useState } from "react";
import Feed from "../components/Feed";
import { api } from "../api";
import type { VideoCard } from "../types";
import { useStore } from "../store";
import { ISearch } from "../icons";
import { Empty } from "../components/ui";

/** 首页一次取多少条。多取一些，随机打散后才有足够的新鲜感。 */
const POOL_SIZE = 30;
const PAGE_SIZE = 10;

/** Fisher–Yates 洗牌（就地改动副本，返回新数组）。 */
function shuffle<T>(list: T[]): T[] {
  const out = [...list];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * 首页。
 *
 * 上游的 `/api/videos` 是固定顺序（热榜式），每天看到的第一条几乎不变。
 * 这里多页拉一个候选池，打散后再喂给播放器——刷新一次换一批，
 * 只在「本次会话第一次进首页」时洗牌，翻页追加的部分也各自打散，避免往下滑时又是固定顺序。
 */
export default function Home({ active, bottomInset }: { active: boolean; bottomInset: number }) {
  const { toast } = useStore();
  const [items, setItems] = useState<VideoCard[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");
  const loadingRef = useRef(false);
  /** 已展示过的 id，用来在后续翻页里剔除重复 */
  const seenRef = useRef<Set<number>>(new Set());

  const load = useCallback(async (p: number) => {
    if (loadingRef.current || done) return;
    loadingRef.current = true;
    setLoading(true);
    setError("");
    try {
      // 第一页多取（候选池），后续按正常页大小追加
      const size = p === 1 ? POOL_SIZE : PAGE_SIZE;
      const res = await api.feed(p, size);
      const list = res?.items || [];
      const fresh = list.filter((x) => !seenRef.current.has(x.id));
      fresh.forEach((x) => seenRef.current.add(x.id));
      // 每条都打散：翻页时不会又变成上游的固定顺序
      const mixed = shuffle(fresh);
      setItems((prev) => [...prev, ...mixed]);
      setPage(p);
      if (!list.length || (res?.pagination && p >= res.pagination.pages)) setDone(true);
    } catch (e) {
      const message = (e as Error).message || "加载失败";
      setError(message);
      toast(message, "info");
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [done, toast]);

  useEffect(() => { if (!items.length) load(1); /* eslint-disable-next-line */ }, []);

  const ids = items.map((v) => v.id);

  return (
    <div className="absolute inset-0 bg-black">
      {items.length ? (
        <Feed videoIds={ids} mode="home" active={active} bottomInset={bottomInset}
          onNearEnd={() => { if (!loading && !done) load(page + 1); }} />
      ) : !loading && error ? (
        <div className="absolute inset-0 flex items-center justify-center bg-bg">
          <Empty icon={<ISearch size={26} />} title="首页加载失败" sub={error} action="重试" onAction={() => void load(1)} />
        </div>
      ) : !loading && done ? (
        <div className="absolute inset-0 flex items-center justify-center bg-bg"><Empty icon={<ISearch size={26} />} title="暂无视频" /></div>
      ) : (
        <div className="absolute inset-0 flex items-center justify-center"><div className="w-9 h-9 spinner" /></div>
      )}
    </div>
  );
}
