"""An attached guest, as the kvmi shell's introspection and profile commands do it."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from rootview_web.deps import get_engine, same_origin, writes_allowed
from rootview_web.engine import GuestPool
from rootview_web.engine.schemas import (
    FieldInfo,
    Hex,
    KernelInfo,
    Memory,
    Register,
    RegisterWrite,
    Space,
    Symbol,
    Task,
    Translation,
)

router = APIRouter(prefix="/api/vms/{vm_id}", tags=["guest"])
mutating = [Depends(same_origin)]
writing = [Depends(same_origin), Depends(writes_allowed)]

MEMORY_MAX = 1 << 16
READERS = {Space.PHYS: "read_phys", Space.VIRT: "read_virt", Space.KERNEL: "read"}
WRITERS = {Space.PHYS: "write_phys", Space.VIRT: "write_virt"}


def _type_name(t) -> str:
    return f"{t.kind} {t.name}" if t.name else f"{t.kind} <anon>"


def _format(kind: str, value: int | str | bytes) -> str:
    if kind == "ptr":
        return f"{value:#x}"
    if kind == "bytes":
        return value.hex()
    return str(value)


@router.get("/kernel", response_model=KernelInfo)
async def kernel(vm_id: str, engine: GuestPool = Depends(get_engine)) -> KernelInfo:
    info = await engine.guest(vm_id, lambda g: g.info())
    return KernelInfo.model_validate(info, from_attributes=True)


@router.post("/pause", status_code=204, dependencies=mutating)
async def pause(vm_id: str, engine: GuestPool = Depends(get_engine)) -> None:
    await engine.guest(vm_id, lambda g: g.pause())


@router.post("/resume", status_code=204, dependencies=mutating)
async def resume(vm_id: str, engine: GuestPool = Depends(get_engine)) -> None:
    await engine.guest(vm_id, lambda g: g.resume())


@router.post("/profile", status_code=204, dependencies=mutating)
async def profile(vm_id: str, engine: GuestPool = Depends(get_engine)) -> None:
    await engine.guest(vm_id, lambda g: g.load_profile())
    engine.profile_errors.pop(vm_id, None)


@router.get("/memory", response_model=Memory)
async def read_memory(
    vm_id: str,
    addr: Hex,
    length: int = Query(gt=0, le=MEMORY_MAX),
    space: Space = Space.KERNEL,
    engine: GuestPool = Depends(get_engine),
) -> Memory:
    data = await engine.guest(vm_id, lambda g: getattr(g, READERS[space])(addr, length))
    return Memory(space=space, addr=addr, data=data)


@router.put("/memory", status_code=204, dependencies=writing)
async def write_memory(vm_id: str, body: Memory, engine: GuestPool = Depends(get_engine)) -> None:
    writer = WRITERS.get(body.space)
    if writer is None:
        raise HTTPException(status_code=422, detail="kernel space is read-only; write through phys or virt")
    await engine.guest(vm_id, lambda g: getattr(g, writer)(body.addr, body.data))


@router.get("/translate", response_model=Translation)
async def translate(vm_id: str, addr: Hex, engine: GuestPool = Depends(get_engine)) -> Translation:
    return Translation(va=addr, pa=await engine.guest(vm_id, lambda g: g.translate(addr)))


@router.get("/registers", response_model=dict[str, Hex])
async def registers(vm_id: str, engine: GuestPool = Depends(get_engine)) -> dict[str, int]:
    return await engine.guest(vm_id, lambda g: g.regs())


@router.get("/registers/{name}", response_model=Register)
async def register(vm_id: str, name: str, engine: GuestPool = Depends(get_engine)) -> Register:
    return Register(name=name, value=await engine.guest(vm_id, lambda g: g.reg(name)))


@router.put("/registers/{name}", status_code=204, dependencies=writing)
async def set_register(vm_id: str, name: str, body: RegisterWrite, engine: GuestPool = Depends(get_engine)) -> None:
    await engine.guest(vm_id, lambda g: g.set_reg(name, body.value))


@router.get("/tasks", response_model=list[Task])
async def tasks(vm_id: str, engine: GuestPool = Depends(get_engine)) -> list[Task]:
    return [Task.model_validate(t, from_attributes=True) for t in await engine.guest(vm_id, lambda g: g.tasks())]


@router.get("/symbols/{name}", response_model=Symbol)
async def symbol(vm_id: str, name: str, engine: GuestPool = Depends(get_engine)) -> Symbol:
    def lookup(g):
        addr = g.sym(name)
        try:
            return g.sym_at(addr)[0].type, addr
        except engine.prim.RootviewError:
            return "", addr

    kind, addr = await engine.guest(vm_id, lookup)
    return Symbol(name=name, addr=addr, type=kind)


@router.get("/symbols", response_model=Symbol)
async def symbol_at(vm_id: str, addr: Hex, engine: GuestPool = Depends(get_engine)) -> Symbol:
    sym, offset = await engine.guest(vm_id, lambda g: g.sym_at(addr))
    return Symbol(name=sym.name, addr=sym.addr, type=sym.type, offset=offset)


@router.get("/fields", response_model=FieldInfo)
async def field(
    vm_id: str, type: str, path: str, addr: Hex | None = None, engine: GuestPool = Depends(get_engine)
) -> FieldInfo:
    def resolve(g):
        f = g.field(type, path)
        names = _type_name(g.btf_type(f.type)), _type_name(g.btf_type(f.ref)) if f.ref else None
        return f, names, None if addr is None else g.read_field(type, path, addr)

    f, (type_name, ref_name), v = await engine.guest(vm_id, resolve)
    out = FieldInfo(
        type=type,
        path=path,
        type_name=type_name,
        ref_name=ref_name,
        **{k: getattr(f, k) for k in ("offset", "size", "bit_off", "bit_size", "kind")},
    )
    if v is not None:
        out.value = _format(v.kind, v.value) if v.kind != "enum" else v.enum_name or str(v.value)
        out.length = v.length or None
    return out
