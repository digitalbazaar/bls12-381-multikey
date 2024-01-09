/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
export function assertArray(value, name) {
  if(!Array.isArray(value)) {
    throw new TypeError(`"${name}" must be an array.`);
  }
}

export function assertInstance(type, value, name) {
  if(!(value instanceof type)) {
    throw new TypeError(`"${name}" must be a ${type.name}.`);
  }
}

export function assertType(type, value, name) {
  if(typeof value !== type) {
    const aOrAn = type === 'object' ? 'an' : 'a';
    throw new TypeError(`"${name}" must be ${aOrAn} ${type}.`);
  }
}
