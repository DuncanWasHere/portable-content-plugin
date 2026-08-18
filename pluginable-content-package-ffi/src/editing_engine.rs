use super::*;

pub(crate) fn frame_subrecord(signature: Signature, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut writer = RecordWriter::new(
        Signature::from_bytes(*b"TEMP"),
        RecordFlags::default(),
        RecordId::from_raw(0),
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    );
    writer
        .write_subrecord(signature, payload)
        .map_err(|error| error.to_string())?;
    Ok(writer.finish().map_err(|error| error.to_string())?[RecordHeader::BYTE_COUNT..].to_vec())
}

pub(crate) fn subrecord_ranges(
    payload: &[u8],
) -> Result<Vec<(Signature, std::ops::Range<usize>)>, String> {
    let mut ranges = Vec::new();
    let mut position = 0usize;
    while position < payload.len() {
        let start = position;
        if payload.len() - position < SubrecordHeader::BYTE_COUNT {
            return Err("Truncated subrecord header.".into());
        }
        let header = SubrecordHeader::from_bytes(
            payload[position..position + SubrecordHeader::BYTE_COUNT]
                .try_into()
                .expect("fixed-size slice"),
        );
        position += SubrecordHeader::BYTE_COUNT;
        let field_signature = header.signature();
        let size = header.payload_byte_count() as usize;
        let end = position
            .checked_add(size)
            .ok_or("Subrecord size overflow.")?;
        if end > payload.len() {
            return Err("Subrecord payload exceeds its record.".into());
        }
        ranges.push((field_signature, start..end));
        position = end;
    }
    Ok(ranges)
}

fn update_containing_group_sizes(
    bytes: &mut [u8],
    index: &PackageIndex,
    entry_start: u64,
    entry_end: u64,
    delta: i64,
) -> Result<(), String> {
    for group in index
        .groups()
        .iter()
        .filter(|group| group.payload_offset() <= entry_start && group.end_offset() >= entry_end)
    {
        let size_offset = group.header_offset() as usize + Signature::BYTE_COUNT;
        let size = i64::from(group.header().group_byte_count()) + delta;
        let size = u32::try_from(size).map_err(|_| "Containing group size overflow.")?;
        bytes[size_offset..size_offset + 4].copy_from_slice(&size.to_le_bytes());
    }
    Ok(())
}

pub(crate) fn replace_record(
    bytes: &[u8],
    index: &PackageIndex,
    id: RecordId,
    replacement: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let record = index.record(id).ok_or("Record does not exist.")?;
    let start = record.header_offset() as usize;
    let old_len = RecordHeader::BYTE_COUNT + record.header().payload_byte_count() as usize;
    let new_len = replacement.map_or(0, <[u8]>::len);
    let delta = i64::try_from(new_len).map_err(|_| "Record size overflow.")?
        - i64::try_from(old_len).map_err(|_| "Record size overflow.")?;
    let mut updated = bytes.to_vec();
    update_containing_group_sizes(
        &mut updated,
        index,
        record.header_offset(),
        (start + old_len) as u64,
        delta,
    )?;
    updated.splice(
        start..start + old_len,
        replacement.unwrap_or_default().iter().copied(),
    );
    Ok(updated)
}

pub(crate) fn rewrite_package_header(
    bytes: Vec<u8>,
    package: &Package,
    header: &PackageHeader,
) -> Result<Vec<u8>, String> {
    rewrite_package_header_bytes(bytes, package, header).map_err(|error| error.to_string())
}

pub(crate) fn rebuild_scene_offsets(handle: &mut PcpPackageHandle) -> Result<(), String> {
    let tables = scene_offset_tables_from_index(package_index(handle)?)
        .map_err(|error| error.to_string())?;
    let mut header = handle.package.header().clone();
    header
        .replace_scene_offset_tables(tables)
        .map_err(|error| error.to_string())?;
    let bytes = rewrite_package_header(package_bytes(handle)?.to_vec(), &handle.package, &header)?;
    reopen(handle, bytes)
}

pub(crate) fn insert_record(
    handle: &mut PcpPackageHandle,
    target_group_offset: u64,
    record_signature: u32,
    payload: &[u8],
    requested_id: Option<RecordId>,
) -> Result<RecordId, String> {
    if requested_id.is_none() && handle.package.header().load_class() == PackageLoadClass::Overlay {
        return Err("Overlay packages cannot add records of their own.".into());
    }
    let owned_index = u8::try_from(handle.package.header().dependencies().len())
        .map_err(|_| "Package has too many dependencies.")?;
    let id = requested_id.unwrap_or(
        RecordId::new(owned_index, handle.package.header().next_local_identifier())
            .map_err(|error| error.to_string())?,
    );
    if id.package_index() > owned_index {
        return Err("Inserted record refers to an absent dependency index.".into());
    }
    let is_owned = id.package_index() == owned_index;
    if is_owned && handle.package.header().load_class() == PackageLoadClass::Overlay {
        return Err("Overlay packages cannot add records of their own.".into());
    }
    if package_index(handle)?.record(id).is_some() {
        return Err(format!("Record {id} already exists."));
    }
    let header = RecordHeader::new(
        signature(record_signature),
        u32::try_from(payload.len()).map_err(|_| "Record payload is too large.")?,
        RecordFlags::default(),
        id,
        1.0,
        ChangeSetId::from_bytes([0; 32]),
    )
    .map_err(|error| error.to_string())?;
    let mut framed = header.to_bytes().to_vec();
    framed.extend_from_slice(payload);
    let insertion = if target_group_offset == u64::MAX {
        package_bytes(handle)?.len()
    } else {
        package_index(handle)?
            .groups()
            .iter()
            .find(|group| group.header_offset() == target_group_offset)
            .ok_or("Target group does not exist.")?
            .end_offset() as usize
    };
    let mut bytes = package_bytes(handle)?.to_vec();
    update_containing_group_sizes(
        &mut bytes,
        package_index(handle)?,
        insertion as u64,
        insertion as u64,
        framed.len() as i64,
    )?;
    bytes.splice(insertion..insertion, framed);
    let mut package_header = handle.package.header().clone();
    package_header.set_record_count(package_header.record_count().saturating_add(1));
    if is_owned {
        package_header
            .set_owned_record_count(package_header.owned_record_count().saturating_add(1));
        package_header
            .set_next_local_identifier(
                package_header
                    .next_local_identifier()
                    .max(id.local_identifier().saturating_add(1)),
            )
            .map_err(|error| error.to_string())?;
    }
    let bytes = rewrite_package_header(bytes, &handle.package, &package_header)?;
    reopen(handle, bytes)?;
    Ok(id)
}

#[derive(Debug)]
struct BatchByteEdit {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
    insertion_group_offset: Option<u64>,
    ordinal: usize,
}

pub(crate) fn apply_record_batch(
    handle: &mut PcpPackageHandle,
    mutations: &[PcpRecordMutation],
) -> Result<(), String> {
    if mutations.is_empty() {
        return Ok(());
    }

    let source = package_bytes(handle)?;
    let index = package_index(handle)?;
    let owned_index = u8::try_from(handle.package.header().dependencies().len())
        .map_err(|_| "Package has too many dependencies.")?;
    let mut seen = HashSet::with_capacity(mutations.len());
    let mut edits = Vec::with_capacity(mutations.len());
    let mut record_delta = 0i64;
    let mut owned_delta = 0i64;
    let mut next_local = handle.package.header().next_local_identifier();

    for (ordinal, mutation) in mutations.iter().enumerate() {
        if mutation.reserved != 0 {
            return Err("Record mutation reserved fields must be zero.".into());
        }
        if mutation.payload.is_null() && mutation.payload_byte_count != 0 {
            return Err("A non-empty record mutation payload has a null pointer.".into());
        }
        let id = RecordId::from_raw(mutation.record_id);
        if !seen.insert(id) {
            return Err(format!(
                "Record {id} occurs more than once in the mutation batch."
            ));
        }
        let payload = if mutation.payload_byte_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(mutation.payload, mutation.payload_byte_count) }
        };
        if mutation.kind != 2 {
            subrecord_ranges(payload)?;
        }

        match mutation.kind {
            0 => {
                let record = index
                    .record(id)
                    .ok_or_else(|| format!("Record {id} does not exist."))?;
                let header = RecordHeader::new(
                    record.header().signature(),
                    u32::try_from(payload.len()).map_err(|_| "Record payload is too large.")?,
                    record.header().flags(),
                    id,
                    record.header().version(),
                    record.header().last_change_set(),
                )
                .map_err(|error| error.to_string())?;
                let mut replacement = header.to_bytes().to_vec();
                replacement.extend_from_slice(payload);
                let start = record.header_offset() as usize;
                let end = start
                    + RecordHeader::BYTE_COUNT
                    + record.header().payload_byte_count() as usize;
                edits.push(BatchByteEdit {
                    start,
                    end,
                    replacement,
                    insertion_group_offset: None,
                    ordinal,
                });
            }
            1 => {
                if id.package_index() > owned_index {
                    return Err("Inserted record refers to an absent dependency index.".into());
                }
                let is_owned = id.package_index() == owned_index;
                if is_owned && handle.package.header().load_class() == PackageLoadClass::Overlay {
                    return Err("Overlay packages cannot add records of their own.".into());
                }
                if index.record(id).is_some() {
                    return Err(format!("Record {id} already exists."));
                }
                let header = RecordHeader::new(
                    signature(mutation.record_signature),
                    u32::try_from(payload.len()).map_err(|_| "Record payload is too large.")?,
                    RecordFlags::default(),
                    id,
                    1.0,
                    ChangeSetId::from_bytes([0; 32]),
                )
                .map_err(|error| error.to_string())?;
                let mut replacement = header.to_bytes().to_vec();
                replacement.extend_from_slice(payload);
                let insertion_group_offset = (mutation.target_group_offset != u64::MAX)
                    .then_some(mutation.target_group_offset);
                let start = match insertion_group_offset {
                    Some(offset) => index
                        .groups()
                        .iter()
                        .find(|group| group.header_offset() == offset)
                        .ok_or("Target group does not exist.")?
                        .end_offset() as usize,
                    None => source.len(),
                };
                edits.push(BatchByteEdit {
                    start,
                    end: start,
                    replacement,
                    insertion_group_offset,
                    ordinal,
                });
                record_delta += 1;
                if is_owned {
                    owned_delta += 1;
                    next_local = next_local.max(id.local_identifier().saturating_add(1));
                }
            }
            2 => {
                let record = index
                    .record(id)
                    .ok_or_else(|| format!("Record {id} does not exist."))?;
                let start = record.header_offset() as usize;
                let end = start
                    + RecordHeader::BYTE_COUNT
                    + record.header().payload_byte_count() as usize;
                edits.push(BatchByteEdit {
                    start,
                    end,
                    replacement: Vec::new(),
                    insertion_group_offset: None,
                    ordinal,
                });
                record_delta -= 1;
                if id.package_index() == owned_index {
                    owned_delta -= 1;
                }
            }
            value => return Err(format!("Unknown record mutation kind {value}.")),
        }
    }

    edits.sort_by_key(|edit| (edit.start, edit.ordinal));
    let mut previous_end = 0usize;
    for edit in &edits {
        if edit.start < previous_end {
            return Err("Record mutations overlap in the source package.".into());
        }
        previous_end = previous_end.max(edit.end);
    }

    // Accumulate group deltas.
    let mut groups = index.groups().iter().collect::<Vec<_>>();
    groups.sort_by_key(|group| group.header_offset());
    let mut parents = HashMap::<u64, Option<u64>>::with_capacity(groups.len());
    let mut group_stack = Vec::new();
    for group in &groups {
        while group_stack.last().is_some_and(
            |parent: &&pluginable_content_package_core::GroupView| {
                parent.end_offset() <= group.header_offset()
            },
        ) {
            group_stack.pop();
        }
        parents.insert(
            group.header_offset(),
            group_stack.last().map(|parent| parent.header_offset()),
        );
        group_stack.push(*group);
    }

    let mut group_deltas = HashMap::<u64, i64>::new();
    let mut structural_edits = edits
        .iter()
        .filter(|edit| edit.insertion_group_offset.is_none())
        .collect::<Vec<_>>();
    structural_edits.sort_by_key(|edit| edit.start);
    group_stack.clear();
    let mut next_group = 0usize;
    for edit in structural_edits {
        while next_group < groups.len() && groups[next_group].header_offset() < edit.start as u64 {
            let group = groups[next_group];
            while group_stack
                .last()
                .is_some_and(|parent| parent.end_offset() <= group.header_offset())
            {
                group_stack.pop();
            }
            group_stack.push(group);
            next_group += 1;
        }
        while group_stack
            .last()
            .is_some_and(|group| group.end_offset() < edit.end as u64)
        {
            group_stack.pop();
        }
        let delta = i64::try_from(edit.replacement.len()).map_err(|_| "Record size overflow.")?
            - i64::try_from(edit.end - edit.start).map_err(|_| "Record size overflow.")?;
        for group in &group_stack {
            *group_deltas.entry(group.header_offset()).or_default() += delta;
        }
    }

    for edit in edits
        .iter()
        .filter(|edit| edit.insertion_group_offset.is_some())
    {
        let delta = i64::try_from(edit.replacement.len()).map_err(|_| "Record size overflow.")?;
        let mut group_offset = edit.insertion_group_offset;
        while let Some(offset) = group_offset {
            *group_deltas.entry(offset).or_default() += delta;
            group_offset = parents[&offset];
        }
    }

    let mut patched = source.to_vec();
    for group in groups {
        let delta = group_deltas
            .get(&group.header_offset())
            .copied()
            .unwrap_or(0);
        if delta != 0 {
            let size = u32::try_from(i64::from(group.header().group_byte_count()) + delta)
                .map_err(|_| "Containing group size overflow.")?;
            let size_offset = group.header_offset() as usize + Signature::BYTE_COUNT;
            patched[size_offset..size_offset + 4].copy_from_slice(&size.to_le_bytes());
        }
    }

    let replacement_bytes = edits
        .iter()
        .map(|edit| edit.replacement.len())
        .sum::<usize>();
    let removed_bytes = edits
        .iter()
        .map(|edit| edit.end - edit.start)
        .sum::<usize>();
    let capacity = patched
        .len()
        .checked_add(replacement_bytes)
        .and_then(|value| value.checked_sub(removed_bytes))
        .ok_or("Resulting package size overflow.")?;
    let mut rewritten = Vec::with_capacity(capacity);
    let mut cursor = 0usize;
    for edit in edits {
        rewritten.extend_from_slice(&patched[cursor..edit.start]);
        rewritten.extend_from_slice(&edit.replacement);
        cursor = edit.end;
    }
    rewritten.extend_from_slice(&patched[cursor..]);

    let mut package_header = handle.package.header().clone();
    let record_count = u32::try_from(i64::from(package_header.record_count()) + record_delta)
        .map_err(|_| "Package record count overflow.")?;
    let owned_record_count =
        u32::try_from(i64::from(package_header.owned_record_count()) + owned_delta)
            .map_err(|_| "Package owned-record count overflow.")?;
    package_header.set_record_count(record_count);
    package_header.set_owned_record_count(owned_record_count);
    package_header
        .set_next_local_identifier(next_local)
        .map_err(|error| error.to_string())?;
    let rewritten = rewrite_package_header(rewritten, &handle.package, &package_header)?;
    reopen(handle, rewritten)
}
