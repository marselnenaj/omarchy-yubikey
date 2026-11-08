import QtQuick
import QtTest
import qs.Commons as Commons
import "Setup" as Setup
TestCase {
  name: "ControlPanel"
  property var panel
  property int emitted: 0
  property var lastParameters
  when: false
  property string screenshotDirectory: ""
  Component { id: buttonFixture; Setup.ActionButton { text: "Primary action"; primary: true } }
  function test_button_states() {
    var original = {background: Commons.Color.background, foreground: Commons.Color.foreground, accent: Commons.Color.accent}
    var button = buttonFixture.createObject(panel, {x: 40, y: 80, z: 100})
    verify(button !== null)
    function luminance(color) {
      function linear(value) { return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4) }
      return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
    }
    var paletteName = ""
    function readable(state) {
      wait(200) // Let the host's color and press animations settle.
      var image = grabImage(button)
      if (screenshotDirectory !== "") image.save(screenshotDirectory + "/button-" + paletteName + "-" + state + ".png")
      if (button.color.a <= 0.99) throw new Error("Primary fill disappeared: " + paletteName + " / " + state)
      var pixel = image.pixel(8, Math.floor(image.height / 2))
      verify(pixel.a > 0.99, "Rendered primary surface must stay opaque in " + state)
      var text = luminance(button.foreground), fill = luminance(pixel)
      verify((Math.max(text, fill) + 0.05) / (Math.min(text, fill) + 0.05) >= 4.5,
             "Primary text must remain readable in " + state)
    }
    try {
      var clicks = 0
      button.clicked.connect(function() { clicks++ })
      for (var palette of [
        {name:"dark", background:"#1a1b26", foreground:"#a9b1d6", accent:"#7aa2f7"},
        {name:"light", background:"#ffffff", foreground:"#172554", accent:"#1d4ed8"}
      ]) {
        paletteName = palette.name
        Commons.Color.background = palette.background
        Commons.Color.foreground = palette.foreground
        Commons.Color.accent = palette.accent
        panel.forceActiveFocus()
        mouseMove(panel, 2, 2)
        verify(!button.activeFocus)
        readable("idle")
        mouseMove(button, button.width / 2, button.height / 2)
        tryCompare(button, "hot", true)
        readable("hover")
        mousePress(button, button.width / 2, button.height / 2)
        readable("pressed")
        mouseRelease(button, button.width / 2, button.height / 2)
        mouseMove(panel, 2, 2)
        button.forceActiveFocus()
        verify(button.activeFocus)
        readable("focus")
        var before = clicks
        keyClick(Qt.Key_Space)
        compare(clicks, before + 1)
        // A runtime switch back to secondary must restore the host binding.
        button.primary = false
        wait(200)
        verify(button.color.a < 0.99)
        compare(button.foreground, Commons.Color.foreground)
        button.primary = true
        readable("primary-again")
        button.enabled = false
        before = clicks
        mouseClick(button, button.width / 2, button.height / 2)
        compare(clicks, before)
        verify(button.opacity < 1)
        button.enabled = true
      }
    } finally {
      button.destroy()
      Commons.Color.background = original.background
      Commons.Color.foreground = original.foreground
      Commons.Color.accent = original.accent
    }
  }
  function test_actions_and_keyboard() {
    var originalSnapshot = panel.snapshot
    verify(panel.width > 0)
    var translations = findChild(panel, "setupTranslations")
    verify(translations !== null)
    compare(typeof translations.number, "function")
    compare(translations.number(12).length, 2)
    function checkTabs(item) {
      if (item.objectName === "sidebarTab" && !panel.compact)
        verify(item.implicitWidth <= item.width, "Navigation label must fit its button")
      if (item.children) for (var i=0;i<item.children.length;i++) checkTabs(item.children[i])
    }
    checkTabs(panel)
    panel.operationRequested.connect(function(action, parameters) { emitted++; lastParameters=parameters })
    panel.ask("setup-sudo", "Configure sudo")
    var dialog = findChild(panel,"actionConfirmation")
    verify(dialog.opened)
    compare(dialog.selectedIndex,0)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(emitted,0)
    panel.ask("luks-enroll", "Enroll disk key", "/dev/example")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(emitted,1)
    compare(lastParameters[0],"--device")
    compare(lastParameters[1],"/dev/example")
    panel.ask("rollback","Restore","","../../bad")
    compare(dialog.opened,false)
    panel.ask("setup", "Guided setup")
    keyClick(Qt.Key_Escape)
    compare(dialog.opened,false)
    var closed = 0
    panel.closeRequested.connect(function() { closed++ })
    panel.focusFirst()
    keyClick(Qt.Key_Escape)
    compare(closed,1)
    panel.page = 1
    wait(30)
    function checkPublicFields(item) {
      if (item.readOnly === true && item.selectByMouse === true && item.visible) {
        var point = item.mapToItem(panel, 0, 0)
        verify(point.x >= -1 && point.x + item.width <= panel.width + 1, "Public identity field must fit horizontally")
        verify(item.contentWidth <= item.width + 1, "Long fingerprints must wrap within the field")
      }
      if (item.children) for (var i=0;i<item.children.length;i++) checkPublicFields(item.children[i])
    }
    checkPublicFields(panel)
    var openpgpCard = findChild(panel,"openpgpCard")
    verify(openpgpCard.visible)
    var openpgpImport = findChild(panel,"openpgpImport")
    var openpgpRemove = findChild(panel,"openpgpRemove")
    function openpgpAction(button) {
      button.clicked()
      var action = panel.pendingAction
      keyClick(Qt.Key_Escape)
      compare(dialog.opened,false)
      return action
    }
    // Ready key: the import button offers an update, not highlighted; removal is separate.
    var updateText = openpgpImport.text
    verify(!openpgpImport.primary)
    compare(openpgpAction(openpgpImport), "openpgp-import")
    verify(openpgpRemove.enabled)
    compare(openpgpAction(openpgpRemove), "openpgp-remove")
    var savedOpenpgp = panel.snapshot.openpgp
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:false,linked:false,trusted:false,ready:false,key:null}})
    verify(openpgpImport.text !== updateText)
    verify(openpgpImport.primary)
    verify(!openpgpRemove.enabled)
    compare(openpgpAction(openpgpImport), "openpgp-import")
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:false,trusted:true,ready:false,key:{algorithm:"ed25519"}}})
    compare(openpgpImport.text, updateText)
    verify(openpgpImport.primary)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:true,ready:true,key:{algorithm:"ed25519",expired:true}}})
    verify(openpgpImport.primary)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:savedOpenpgp})
    var details = findChild(panel,"openpgpDetails")
    verify(details.visible)
    compare(panel.openpgpDetails().length, 9)
    verify(openpgpCard.ready)
    var identityToggle = findChild(panel,"openpgpIdentityToggle")
    verify(identityToggle.visible)
    identityToggle.clicked()
    compare(panel.openpgpDetails().length, 10)
    identityToggle.clicked()
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:true,key:{algorithm:"ed25519",sign:true,encrypt:true,authenticate:false,expires:"2020-01-01",expired:true,uids:1}}})
    verify(!openpgpCard.ready)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,ready:true,key:{algorithm:"ed25519",revoked:true}}})
    verify(!openpgpCard.ready)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:false,key:null}})
    verify(!details.visible)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:false,imported:false,linked:false,trusted:false,key:null}})
    verify(!openpgpCard.visible)
    panel.snapshot = Object.assign({}, panel.snapshot, {openpgp:{card:true,imported:true,linked:true,trusted:false,key:{algorithm:"ed25519",sign:true,encrypt:true,authenticate:true,expires:"2030-01-01",expired:false,uids:2}}})
    var sshCard = findChild(panel,"sshCard")
    verify(sshCard.visible)
    verify(findChild(panel,"sshKeys").visible)
    // Each row: one button removes the copy, the other deletes the key itself.
    compare(panel.sshKeyTitle({application:"ssh:github.com", user:"work"}), "ssh:github.com · work")
    compare(panel.sshKeyTitle({application:"ssh:github.com", user:""}), "ssh:github.com")
    compare(panel.sshKeyTitle({application:"ssh:", user:"0102030405060708090a0b0c0d0e0f10"}), "ssh: · 0102030405060708…")
    var remove = findChild(panel,"sshRemove0")
    var deleteKey = findChild(panel,"sshDelete0")
    verify(remove !== null && deleteKey !== null)
    for (var button of [remove, deleteKey]) {
      verify(button.visible && button.width > 0 && button.height > 0, "Row buttons must be laid out")
      var corner = button.mapToItem(panel, 0, 0)
      verify(corner.x >= 0 && corner.x + button.width <= panel.width + 1, "Row buttons must fit the window")
    }
    if (!panel.compact) verify(Math.abs(remove.mapToItem(panel, 0, 0).y - deleteKey.mapToItem(panel, 0, 0).y) < 1, "Row buttons sit side by side")
    // Card-wide actions come before the key boxes; each key's buttons sit inside its box.
    var importButton = findChild(panel,"sshImport")
    var firstBox = findChild(panel,"sshKeyBox0")
    verify(importButton.mapToItem(panel, 0, 0).y + importButton.height < firstBox.mapToItem(panel, 0, 0).y, "Import/Create precede the keys")
    var inBox = remove.mapToItem(firstBox, 0, 0)
    verify(inBox.y >= 0 && inBox.y + remove.height <= firstBox.height, "A key's buttons stay inside its box")
    verify(deleteKey.foreground.toString() !== remove.foreground.toString(), "The permanent action must stand out from removing a copy")
    remove.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-remove")
    verify(dialog.message.indexOf(panel.sshDeleteWarning) < 0, "Removing a copy is not a permanent deletion")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(lastParameters.length,2)
    compare(lastParameters[0],"--key-id")
    compare(lastParameters[1],"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    deleteKey.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-delete")
    verify(dialog.message.indexOf(panel.sshDeleteWarning) >= 0, "The confirmation must carry the permanent-deletion warning")
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(lastParameters[0],"--key-id")
    compare(lastParameters[1],"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    var create = findChild(panel,"sshCreate")
    verify(create.visible && create.enabled)
    create.clicked()
    verify(dialog.opened)
    compare(panel.pendingAction,"ssh-create")
    verify(dialog.message.indexOf(panel.sshDeleteWarning) < 0)
    keyClick(Qt.Key_Right)
    keyClick(Qt.Key_Return)
    compare(dialog.opened,false)
    compare(lastParameters.length,0)
    verify(findChild(panel,"sshDeleteToken") === null)
    panel.page = 0
    panel.snapshot = Object.assign({}, panel.snapshot, {operation:{phase:"running"}})
    panel.ask("setup", "Guided setup")
    compare(dialog.opened,false)
    panel.snapshot = Object.assign({}, panel.snapshot, {operation:{}})
    panel.notice = ""
    panel.failed = false
    for (var page=0;page<5;page++) {
      panel.page=page; wait(30); verify(panel.height>0)
      var scroll = findChild(panel,"contentScroll")
      if (scroll.contentHeight > scroll.availableHeight) {
        scroll.contentItem.contentY = scroll.contentHeight - scroll.availableHeight
        verify(scroll.contentItem.contentY > 0)
        scroll.contentItem.contentY = 0
      }
    }
    panel.snapshot = originalSnapshot
  }
}
