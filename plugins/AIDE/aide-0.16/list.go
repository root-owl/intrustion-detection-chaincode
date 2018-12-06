package aide

import (
	"container/list"
	"errors"
)

type CompareType = func(n1 interface{}, n2 interface{}) (int)

/* list_sorted_insert()
 * Adds an item in a sorted list:
 *   - The first argument is the head of the list
 *   - The second argument is the data to be added
 *   - The third argument is the function pointer to the compare function to use
 *   - Returns the head of the list
 */
func list_sorted_insert(listp *list.List, data interface{}, compare CompareType) (*list.List, error) {

	if listp == nil {
		return nil, errors.New("Should not instert anything into null list.")
	} else if data == nil {
		return listp, nil
	}

	if listp.Len() == 0 {
		listp.PushFront(data)
		return listp, nil
	}

	var curItem = listp.Front()
	//newItem := new(list.Element)
	//newItem.Value = data
	for ; compare(data, curItem.Value) > 0 && curItem.Next() != nil; {
		curItem = curItem.Next()
	}

	if curItem.Next() == nil && compare(data, curItem.Value) > 0 {
		listp.PushBack(data)
	} else {
		listp.InsertBefore(data, curItem)
	}

	return listp, nil
}

