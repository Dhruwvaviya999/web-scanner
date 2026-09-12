"use client"

import * as React from "react"
import { Select as SelectPrimitive } from "@base-ui/react/select"
import { cn } from "cn"
import { ChevronDownIcon, CheckIcon, ChevronUpIcon } from "lucide-react"

const Select = SelectPrimitive.Root

function SelectGroup({ className, ...props }: SelectPrimitive.Group.Props) {
  // The panel carries the padding now (see SelectContent) — a group repeating
  // it would inset its rows twice.
  return (
    <SelectPrimitive.Group
      data-slot="select-group"
      className={cn("scroll-my-1", className)}
      {...props}
    />
  )
}

function SelectValue({ className, ...props }: SelectPrimitive.Value.Props) {
  return (
    <SelectPrimitive.Value
      data-slot="select-value"
      className={cn("flex flex-1 text-left", className)}
      {...props}
    />
  )
}

function SelectTrigger({
  className,
  size = "default",
  children,
  ...props
}: SelectPrimitive.Trigger.Props & {
  size?: "sm" | "default"
}) {
  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size}
      // w-full, not w-fit: a select belongs to the field it sits in, and a
      // trigger that collapses to its current value changes width as the value
      // changes. Callers that want a fixed filter width pass one, and their
      // class wins — every existing call site already does.
      className={cn(
        "flex w-full cursor-pointer items-center justify-between gap-1.5 rounded-lg border border-input bg-transparent py-2 pr-2 pl-2.5 text-sm whitespace-nowrap transition-colors outline-none select-none hover:border-ring/60 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 data-placeholder:text-muted-foreground data-[size=default]:h-8 data-[size=sm]:h-7 data-[size=sm]:rounded-[min(var(--radius-md),10px)] *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-1.5 dark:bg-input/30 dark:hover:bg-input/50 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon
        render={
          <ChevronDownIcon className="pointer-events-none size-4 text-muted-foreground" />
        }
      />
    </SelectPrimitive.Trigger>
  )
}

/**
 * How the panel is placed.
 *
 * - `popper` — the panel floats below (or above) the trigger, like any other
 *   popover. Predictable, and the only mode in which `side`, `align` and the
 *   offsets mean anything.
 * - `item-aligned` — the panel overlaps the trigger so the selected option's
 *   text sits over the trigger's value, the way a native macOS select behaves.
 *
 * Base UI spells this `alignItemWithTrigger` and defaults it to `true`; the
 * name and the default here follow the Radix convention the rest of the
 * codebase's mental model is built on. Note that Base UI applies item-aligning
 * for mouse input only, and drops it when there is not enough room — so it is a
 * preference, not a guarantee.
 */
type SelectPosition = "popper" | "item-aligned"

function SelectContent({
  className,
  children,
  side = "bottom",
  // Lifts the panel off the trigger so the two read as separate surfaces, and
  // does it in a way the positioner can measure. A `translate-y` on the popup
  // would be applied after Base UI has measured, so the panel would sit flush
  // against the trigger for collision purposes and only look offset — and not
  // at all once it flipped above. 8 matches the other floating surfaces.
  //
  // This only has an effect in `popper` mode; item-aligning ignores offsets.
  sideOffset = 8,
  position = "popper",
  align = "center",
  alignOffset = 0,
  ...props
}: SelectPrimitive.Popup.Props &
  Pick<
    SelectPrimitive.Positioner.Props,
    "align" | "alignOffset" | "side" | "sideOffset"
  > & { position?: SelectPosition }) {
  const itemAligned = position === "item-aligned"

  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Positioner
        side={side}
        sideOffset={sideOffset}
        align={align}
        alignOffset={alignOffset}
        alignItemWithTrigger={itemAligned}
        className="isolate z-50"
      >
        <SelectPrimitive.Popup
          data-slot="select-content"
          data-align-trigger={itemAligned}
          // p-1: without it the first and last rows sit flush against the panel
          // edge and the list reads as a block of text rather than a panel of
          // options. It lives here rather than on SelectGroup so ungrouped
          // items get it too.
          className={cn(
            "relative isolate z-50 max-h-(--available-height) origin-(--transform-origin) overflow-x-hidden overflow-y-auto rounded-lg bg-popover p-1 text-popover-foreground shadow-md ring-1 ring-foreground/10 duration-100 data-[align-trigger=true]:animate-none data-[side=bottom]:slide-in-from-top-2 data-[side=inline-end]:slide-in-from-left-2 data-[side=inline-start]:slide-in-from-right-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95",
            // Exactly the trigger's width, not merely at least it: a floor let
            // any option longer than the trigger widen the panel, so it no
            // longer lined up with the field it belongs to. Long labels
            // truncate instead — see SelectItem.
            !itemAligned && "w-(--anchor-width) max-w-(--available-width)",
            // Item-aligned has no trigger width to size against — the panel is
            // placed by which option is selected — so it sizes to content with
            // the old floor.
            itemAligned && "w-full min-w-36",
            className
          )}
          {...props}
        >
          <SelectScrollUpButton />
          <SelectPrimitive.List>{children}</SelectPrimitive.List>
          <SelectScrollDownButton />
        </SelectPrimitive.Popup>
      </SelectPrimitive.Positioner>
    </SelectPrimitive.Portal>
  )
}

function SelectLabel({
  className,
  ...props
}: SelectPrimitive.GroupLabel.Props) {
  return (
    <SelectPrimitive.GroupLabel
      data-slot="select-label"
      className={cn("px-1.5 py-1 text-xs text-muted-foreground", className)}
      {...props}
    />
  )
}

/**
 * The full label, when it is plain text. Used as a tooltip, because the panel
 * is pinned to the trigger's width and a long option can now be cut off.
 *
 * Handles a children *array* of strings as well as a single one: `{a} {b}`
 * in JSX produces the array, and several call sites are written that way.
 */
function textOf(children: React.ReactNode): string | undefined {
  if (typeof children === "string") return children
  if (Array.isArray(children) && children.every((c) => typeof c === "string")) {
    return children.join("")
  }
  return undefined
}

function SelectItem({
  className,
  children,
  ...props
}: SelectPrimitive.Item.Props) {
  return (
    <SelectPrimitive.Item
      title={textOf(children)}
      data-slot="select-item"
      // min-w-0 lets the label shrink: a flex child defaults to its content
      // width, which would push past the fixed panel width instead of
      // truncating inside it.
      className={cn(
        "relative flex w-full min-w-0 cursor-default items-center gap-1.5 rounded-md py-1 pr-8 pl-1.5 text-sm outline-hidden select-none focus:bg-accent focus:text-accent-foreground not-data-[variant=destructive]:focus:**:text-accent-foreground data-disabled:pointer-events-none data-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 *:[span]:last:flex *:[span]:last:items-center *:[span]:last:gap-2",
        className
      )}
      {...props}
    >
      {/* The inner span is what carries the ellipsis: ItemText is a flex box
          here (gap-2, so an icon and its label sit apart), and text-overflow
          does nothing on a flex container. */}
      <SelectPrimitive.ItemText className="flex min-w-0 flex-1 gap-2">
        <span className="min-w-0 truncate">{children}</span>
      </SelectPrimitive.ItemText>
      <SelectPrimitive.ItemIndicator
        render={
          <span className="pointer-events-none absolute right-2 flex size-4 items-center justify-center" />
        }
      >
        <CheckIcon className="pointer-events-none" />
      </SelectPrimitive.ItemIndicator>
    </SelectPrimitive.Item>
  )
}

function SelectSeparator({
  className,
  ...props
}: SelectPrimitive.Separator.Props) {
  return (
    <SelectPrimitive.Separator
      data-slot="select-separator"
      className={cn("pointer-events-none -mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  )
}

function SelectScrollUpButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollUpArrow>) {
  return (
    <SelectPrimitive.ScrollUpArrow
      data-slot="select-scroll-up-button"
      className={cn(
        "top-0 z-10 flex w-full cursor-default items-center justify-center bg-popover py-1 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    >
      <ChevronUpIcon />
    </SelectPrimitive.ScrollUpArrow>
  )
}

function SelectScrollDownButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollDownArrow>) {
  return (
    <SelectPrimitive.ScrollDownArrow
      data-slot="select-scroll-down-button"
      className={cn(
        "bottom-0 z-10 flex w-full cursor-default items-center justify-center bg-popover py-1 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    >
      <ChevronDownIcon />
    </SelectPrimitive.ScrollDownArrow>
  )
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
}
